//! aprond serves the Apron chat protocol: cmd/aprond's `main` and `run`.
//! The flags, the TOML configuration, and the helpers `run` wires together
//! live in `apron::aprond`.

use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use rust_stdlib::context::Context;
use rust_stdlib::log::slog::{Arg, Logger, TextHandler};
use rust_stdlib::net::{self, http, Listener};
use rust_stdlib::time::{self, Duration};
use rust_stdlib_sys::os::signal::{self, Parent, SIGINT, SIGTERM};
use rust_stdlib_tls::tls;

use apron::aprond::options::Options;
use apron::aprond::settings::{self, Settings};
use apron::aprond::{acme, command_line, debug, email, listener};
use apron::server::email::{EmailSender, LogEmailSender, SendError, SignInEmail};
use apron::server::{self as server, default_config};
use apron::store;
use apron::webauthn::{self, WebAuthn};

fn main() -> ExitCode {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "aprond".to_string());
    let args: Vec<String> = args.collect();
    let options = match command_line(&program, &args) {
        Ok(options) => options,
        Err(code) => return ExitCode::from(u8::try_from(code).unwrap_or(1)),
    };
    let logger = Logger::new(Arc::new(TextHandler::new(std::io::stderr(), None)));
    if let Err(e) = run(&logger, &options) {
        logger.error("server stopped", &["error".into(), Arg::value(e)]);
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

/// Go's `SMTPSender` as the server's `EmailSender`.
struct SmtpEmailSender(email::SmtpSender);

impl EmailSender for SmtpEmailSender {
    fn send_sign_in_code(&self, ctx: &Context, m: &SignInEmail) -> Result<(), SendError> {
        self.0
            .send_sign_in_code(ctx, &m.to, &m.code, m.add, &m.text())
    }
}

/// The HTTP mail API sender as the server's `EmailSender`.
struct HttpEmailSender(email::HttpSender);

impl EmailSender for HttpEmailSender {
    fn send_sign_in_code(&self, ctx: &Context, m: &SignInEmail) -> Result<(), SendError> {
        self.0
            .send_sign_in_code(ctx, &m.to, &m.code, m.add, &m.text())
    }
}

/// A count option as the server's `usize`; Go treats every count at or
/// below 0 as unlimited, as 0 is here.
fn count(n: i64) -> usize {
    usize::try_from(n).unwrap_or(0)
}

/// The rest of main.go's `serverConfig`: the server configuration for
/// `settings`, with WebAuthn built from its relying party.
fn server_config(settings: Settings) -> Result<server::Config, String> {
    let mut config = default_config();
    config.static_dir = settings.static_dir;
    config.allow_any_origin = settings.allow_any_origin;
    config.public_url = settings.public_url;
    config.max_connections = count(settings.max_connections);
    config.messages_per_minute = settings.messages_per_minute;
    config.max_listed_members = count(settings.max_listed_members);
    config.max_private_rooms = count(settings.max_private_rooms);
    config.read_receipts = settings.read_receipts;
    config.welcome = settings.welcome;
    config.client_ip_header = settings.client_ip_header;
    config.roles = settings.roles;
    config.admin_token = settings.admin_token;
    config.disable_push = settings.disable_push;
    config.allow_insecure_push = settings.allow_insecure_push;
    config.push_hosts = settings.push_hosts;
    config.vapid_private_key = settings.vapid_private_key;
    config.vapid_subject = settings.vapid_subject;
    config.upload_dir = settings.upload_dir;
    config.max_upload_bytes = settings.max_upload_bytes;
    config.max_avatar_bytes = settings.max_avatar_bytes;
    config.upload_types = settings.upload_types.clone();
    config.max_message_upload_bytes = settings.max_message_upload_bytes;
    config.max_upload_storage_bytes = settings.max_upload_storage_bytes;
    if let Some(patterns) = settings.origin_patterns {
        config.origin_patterns = Some(patterns);
    }
    config.email_sender = settings.email_sender.map(|sender| -> Arc<dyn EmailSender> {
        match sender {
            settings::EmailSender::Log => Arc::new(LogEmailSender::default()),
            settings::EmailSender::Smtp(smtp) => Arc::new(SmtpEmailSender(smtp)),
            settings::EmailSender::Http(http) => Arc::new(HttpEmailSender(http)),
        }
    });
    config.email_link_url = settings.email_link_url;
    config.apple_app_ids = settings.apple_app_ids;
    config.unfurl = settings.unfurl;
    config.guest_posting = settings.guest_posting;
    config.server = settings.server.clone();
    config.retention = settings.retention;
    config.frame = settings.frame;
    if let Some(rp) = settings.webauthn {
        let web_authn = WebAuthn::new(webauthn::Config {
            rpid: rp.rp_id,
            rp_display_name: rp.rp_display_name.into(),
            rp_origins: rp.rp_origins,
        })
        .map_err(|e| format!("invalid WebAuthn configuration: {e}"))?;
        config.web_authn = Some(Arc::new(web_authn));
    }
    Ok(config)
}

/// Go's `errgroup.Group` over the HTTP servers: the first serve error ends
/// the group's context.
struct Servers<'a> {
    logger: &'a Logger,
    max_listener_connections: i64,
    servers: Vec<http::Server>,
    threads: Vec<JoinHandle<()>>,
    first_error: Arc<Mutex<Option<String>>>,
    cancel: rust_stdlib::context::CancelFunc,
}

impl Servers<'_> {
    fn new_server(handler: Arc<dyn http::Handler>) -> http::Server {
        http::Server {
            handler: Some(handler),
            read_header_timeout: Duration::from_secs(5),
            // Idle keep-alive connections close; WebSockets and streams are
            // hijacked or long-lived requests, which it does not affect.
            idle_timeout: time::MINUTE * 2,
            ..http::Server::default()
        }
    }

    fn listen(&self, addr: &str) -> Result<Box<dyn Listener>, String> {
        let listener = match net::listen("tcp", addr) {
            Ok(listener) => listener,
            Err(e) => {
                // Listeners opened so far close with their servers.
                for srv in &self.servers {
                    let _ = srv.close();
                }
                return Err(e.to_string());
            }
        };
        if self.max_listener_connections > 0 {
            return Ok(listener::limit_listener(
                listener,
                count(self.max_listener_connections),
            ));
        }
        Ok(listener)
    }

    fn serve(&mut self, name: &str, srv: http::Server, listener: Box<dyn Listener>) {
        self.servers.push(srv.clone());
        let addr = listener.addr().map(|a| a.to_string()).unwrap_or_default();
        self.logger.info(
            &format!("{name} listening"),
            &["addr".into(), Arg::value(addr)],
        );
        let (name, first_error, cancel) = (
            name.to_string(),
            self.first_error.clone(),
            self.cancel.clone(),
        );
        self.threads.push(std::thread::spawn(move || {
            let Err(e) = srv.serve(listener) else {
                return;
            };
            if e.downcast_ref::<http::ErrorString>() == Some(&http::ERR_SERVER_CLOSED) {
                return;
            }
            first_error
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_or_insert(format!("{name}: {e}"));
            cancel();
        }));
    }
}

/// Serves until SIGINT or SIGTERM, or until any listener fails, then shuts
/// every server down.
fn run(logger: &Logger, options: &Options) -> Result<(), String> {
    let mut config = server_config(settings::server_settings(options)?)?;
    let (group, cancel) = Context::background().with_cancel();
    let (ctx, _stop) = signal::notify_context(
        Parent::new(&group, group.done().receiver()),
        &[SIGINT, SIGTERM],
    );

    config.store = Some(store::open(&options.store).map_err(|e| e.to_string())?);
    let vapid_subject = config.vapid_subject.clone();
    let public_url = config.public_url.clone();
    let app =
        server::open(config).map_err(|e| format!("restoring state from {}: {e}", options.store))?;
    let mut servers = Servers {
        logger,
        max_listener_connections: options.max_listener_connections,
        servers: Vec::new(),
        threads: Vec::new(),
        first_error: Arc::new(Mutex::new(None)),
        cancel,
    };

    if !options.tls.domains.is_empty() {
        let manager = acme::Manager::new(acme::Config::lets_encrypt(
            options.tls.domains.clone(),
            &options.tls.cache_dir,
            &options.tls.email,
        ));
        let inner = servers.listen(&options.tls.addr)?;
        let listener = tls::Listener::new(inner, Arc::new(manager.tls_config()));
        servers.serve(
            "apron server (https)",
            Servers::new_server(app.handler()),
            Box::new(listener),
        );
        let challenges = servers.listen(&options.tls.http_addr)?;
        servers.serve(
            "ACME challenges and redirects (http)",
            Servers::new_server(manager.http_handler()),
            challenges,
        );
    } else {
        let listener = servers.listen(&options.addr)?;
        servers.serve("apron server", Servers::new_server(app.handler()), listener);
    }
    if !options.debug_addr.is_empty() {
        if !debug::loopback_addr(&options.debug_addr) {
            logger.warn(
                "the debug listener is unauthenticated and not bound to loopback",
                &["addr".into(), Arg::value(options.debug_addr.as_str())],
            );
        }
        let listener = servers.listen(&options.debug_addr)?;
        servers.serve(
            "debug server",
            Servers::new_server(debug::handler()),
            listener,
        );
    }
    logger.info(
        "serving",
        &[
            "store".into(),
            Arg::value(options.store.as_str()),
            "static_dir".into(),
            Arg::value(options.static_dir.as_str()),
            "upload_dir".into(),
            Arg::value(options.upload.dir.as_str()),
        ],
    );
    if !options.push.disable && vapid_subject.is_empty() && !public_url.starts_with("https://") {
        logger.warn("webpush has no VAPID subject, which some push services refuse; set --push.vapid-subject or an https --public-url", &[]);
    }
    if options.push.allow_insecure {
        logger.warn("push accepts http and internal endpoints (--push.allow-insecure); never set it on a reachable server", &[]);
    }
    if options.email.enable && options.email.sender == "log" {
        logger.warn("email sign-in codes are written to this log, not sent; use --email.sender smtp in a deployment", &[]);
    }

    ctx.wait();
    let (shutdown, _cancel) = Context::background().with_timeout(time::SECOND * 10);
    let _ = app.shutdown(&shutdown);
    for srv in &servers.servers {
        if let Err(e) = srv.shutdown(&shutdown) {
            logger.error(
                "graceful shutdown failed",
                &["error".into(), Arg::value(e.to_string())],
            );
        }
    }
    for thread in servers.threads {
        let _ = thread.join();
    }
    let first_error = servers
        .first_error
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take();
    first_error.map_or(Ok(()), Err)
}
