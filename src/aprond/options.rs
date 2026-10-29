//! The `Options` of cmd/aprond/main.go and the subset of
//! github.com/jessevdk/go-flags that main.go uses: long names with group
//! namespaces (`--upload.max-mb`), `default` and `choice` tags, repeated list
//! flags whose first use replaces the default, `-h`/`--help`, and go-flags'
//! error texts and help layout.

use rust_stdlib::strconv;

/// The command line flags, which a TOML file given with `--config` can also
/// set. Each group's namespace is a flag prefix (`--upload.dir`) and a TOML
/// table (`[upload] dir = ...`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub config: String,
    pub print_config: bool,
    pub addr: String,
    pub static_dir: String,
    pub origins: Vec<String>,
    pub allow_any_origin: bool,
    pub public_url: String,
    pub max_connections: i64,
    pub max_listener_connections: i64,
    pub messages_per_minute: i64,
    pub max_listed_members: i64,
    pub max_private_rooms: i64,
    pub read_receipts: bool,
    pub debug_addr: String,
    pub store: String,
    pub client_ip_header: String,
    pub welcome: String,
    pub roles: Vec<String>,
    pub admin_token_file: String,
    pub webauthn: WebAuthnOptions,
    pub upload: UploadOptions,
    pub email: EmailOptions,
    pub push: PushOptions,
    pub tls: TlsOptions,
    pub apple: AppleOptions,
    pub unfurl: UnfurlOptions,
    pub guest: GuestOptions,
    pub server: ServerOptions,
    pub history: HistoryOptions,
    pub frame: FrameOptions,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WebAuthnOptions {
    pub rp_id: String,
    pub origins: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadOptions {
    pub dir: String,
    pub max_mb: i64,
    pub max_avatar_kb: i64,
    pub types: Vec<String>,
    pub max_message_mb: i64,
    pub max_storage_mb: i64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EmailOptions {
    pub enable: bool,
    pub sender: String,
    pub link_url: String,
    pub from: String,
    pub smtp_addr: String,
    pub smtp_user: String,
    pub smtp_password: String,
    pub smtp_insecure: bool,
    pub http_url: String,
    pub http_headers: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PushOptions {
    pub disable: bool,
    pub allow_insecure: bool,
    pub hosts: Vec<String>,
    pub delay: String,
    pub vapid_private_key: String,
    pub vapid_subject: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsOptions {
    pub domains: Vec<String>,
    pub addr: String,
    pub http_addr: String,
    pub cache_dir: String,
    pub email: String,
}

/// An extension Go lacks (docs/DEVIATIONS.md), so its group comes last.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppleOptions {
    pub app_ids: Vec<String>,
}

/// An extension Go lacks (docs/DEVIATIONS.md).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnfurlOptions {
    pub enable: bool,
}

/// An extension Go lacks (docs/DEVIATIONS.md).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GuestOptions {
    pub posting: bool,
}

/// An extension Go lacks (docs/DEVIATIONS.md).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerOptions {
    pub title: String,
    pub description: String,
    pub avatar: String,
}

/// An extension Go lacks (docs/DEVIATIONS.md).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HistoryOptions {
    pub retention: String,
}

/// An extension Go lacks (docs/DEVIATIONS.md).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameOptions {
    pub max_bytes: i64,
    pub max_text_bytes: i64,
    pub max_depth: i64,
    pub max_nodes: i64,
    pub max_id_bytes: i64,
}

/// A borrowed option field. `Int` is Go's `int` and `Int64` its `int64`;
/// both are 64 bits, and the Go type name shows in conversion errors.
pub enum Field<'a> {
    Str(&'a String),
    Bool(&'a bool),
    Int(&'a i64),
    Int64(&'a i64),
    List(&'a Vec<String>),
}

pub enum FieldMut<'a> {
    Str(&'a mut String),
    Bool(&'a mut bool),
    Int(&'a mut i64),
    Int64(&'a mut i64),
    List(&'a mut Vec<String>),
}

/// One option: its struct tags and its field.
pub struct Spec {
    pub long: &'static str,
    pub description: &'static str,
    pub defaults: &'static [&'static str],
    pub choices: &'static [&'static str],
    pub get: fn(&Options) -> Field<'_>,
    pub get_mut: fn(&mut Options) -> FieldMut<'_>,
}

/// A go-flags group: a struct field with `group` and `namespace` tags.
pub struct Group {
    pub name: &'static str,
    pub namespace: &'static str,
    pub options: &'static [Spec],
}

macro_rules! spec {
    ($long:literal, $kind:ident, $($field:ident).+, [$($default:literal),*], [$($choice:literal),*], $description:literal) => {
        Spec {
            long: $long,
            description: $description,
            defaults: &[$($default),*],
            choices: &[$($choice),*],
            get: |o| Field::$kind(&o.$($field).+),
            get_mut: |o| FieldMut::$kind(&mut o.$($field).+),
        }
    };
}

/// The groups in declaration order, as go-flags walks them for help and
/// main.go's printConfig walks them for TOML.
pub static GROUPS: &[Group] = &[
    Group {
        name: "Application Options",
        namespace: "",
        options: &[
            spec!("config", Str, config, [], [], "Load settings from a TOML file; flags given on the command line take precedence (use --print-config for an example)"),
            spec!("print-config", Bool, print_config, [], [], "Print the current settings as TOML and exit"),
            spec!("addr", Str, addr, ["127.0.0.1:8080"], [], "HTTP and WebSocket listen address; :8080 listens on every interface"),
            spec!("static-dir", Str, static_dir, [], [], "Directory containing the built frontend"),
            spec!("origin", List, origins, [], [], "Allowed WebSocket origin pattern; repeat for more (default: localhost, 127.0.0.1, and ::1)"),
            spec!("allow-any-origin", Bool, allow_any_origin, [], [], "Disable WebSocket origin checks"),
            spec!("public-url", Str, public_url, [], [], "External base URL of upload, file, and stream links, such as https://chat.example (default: each request's host, or https://<tls.domain>)"),
            spec!("max-connections", Int, max_connections, [], [], "Maximum concurrent WebSockets; 0 is unlimited"),
            spec!("max-listener-connections", Int, max_listener_connections, [], [], "Maximum concurrent TCP connections on the listener, HTTP included; 0 is unlimited"),
            spec!("messages-per-minute", Int, messages_per_minute, [], [], "Burst of new messages, room_set requests, and /avatar commands per user, refilled over a minute; 0 is unlimited"),
            spec!("max-listed-members", Int, max_listed_members, ["1000"], [], "Members listed per room in room_list and room_update; a larger room lists its most recently active ones and member_count. 0 is unlimited"),
            spec!("max-private-rooms", Int, max_private_rooms, ["20"], [], "Top-level private rooms one user may be in at once, created or added to, such as on a public deployment; 0 is unlimited"),
            spec!("read-receipts", Bool, read_receipts, [], [], "Relay each user's read cursors to everyone in the room, and list them after room_list; without it they go only to the user's own connections (not in the Go aprond)"),
            spec!("debug-addr", Str, debug_addr, [], [], "Listen address for unauthenticated pprof and expvar under /debug/, such as 127.0.0.1:6060; empty disables"),
            spec!("store", Str, store, [], [], "Where state is kept: sqlite:<path> for a SQLite database, or memory to keep nothing across restarts"),
            spec!("client-ip-header", Str, client_ip_header, [], [], "Request header a reverse proxy puts the client's address in, such as X-Forwarded-For (its last entry) or X-Real-IP, for per-client limits; set only behind a proxy that sets it, since a connection without it is refused. IPv6 clients are limited by their /56"),
            spec!("welcome", Str, welcome, [], [], "Markdown clients show on their sign-in screen (server.welcome), such as how this server's sign-in methods fit together (default: general's description, else a summary of how guests and sign-in work here)"),
            spec!("role", List, roles, [], [], "Grant a role to an account as role=user_id or role=email, such as admin=ada, once: the account keeps it until an admin takes it away; repeat for more. admin and mod (or moderator) may create top-level rooms"),
            spec!("admin-token-file", Str, admin_token_file, [], [], "File holding a token that signs in as the user admin from any origin, without a passkey; at least 16 bytes (default: $APRON_ADMIN_TOKEN; unset or empty disables it)"),
        ],
    },
    Group {
        name: "Passkeys",
        namespace: "webauthn",
        options: &[
            spec!("rp-id", Str, webauthn.rp_id, ["localhost"], [], "Passkey relying party domain; empty disables passkeys"),
            spec!("origin", List, webauthn.origins, ["http://localhost:5173", "http://localhost:8080"], [], "Exact frontend origin for passkeys; repeat for more"),
        ],
    },
    Group {
        name: "Uploads",
        namespace: "upload",
        options: &[
            spec!("dir", Str, upload.dir, [], [], "Directory holding uploaded files; upload files the store does not refer to are removed at start"),
            spec!("max-mb", Int64, upload.max_mb, ["5"], [], "Maximum size of one upload, in MiB"),
            spec!("max-avatar-kb", Int64, upload.max_avatar_kb, ["256"], [], "Maximum size of an /avatar image, in KiB (not in the Go aprond)"),
            spec!("type", List, upload.types, ["image/png", "image/jpeg", "image/gif", "image/webp", "audio/webm", "audio/ogg", "audio/mp4"], [], "Type an upload may be, as a MIME type, type/* or */*; repeat for more. A PNG, JPEG, GIF, WebP, WebM, Ogg or MP4 file is typed from its bytes, any other from its declared type (not in the Go aprond)"),
            spec!("max-message-mb", Int64, upload.max_message_mb, ["20"], [], "Maximum total size of one message's uploads, in MiB"),
            spec!("max-storage-mb", Int64, upload.max_storage_mb, ["1000"], [], "Total size of hosted uploads, in MiB, beyond which the oldest are removed from their messages"),
        ],
    },
    Group {
        name: "Email sign-in",
        namespace: "email",
        options: &[
            spec!("enable", Bool, email.enable, [], [], "Offer email sign-in (off by default)"),
            spec!("sender", Str, email.sender, ["smtp"], ["smtp", "http", "log"], "How email sign-in codes are delivered, with --email.enable: smtp sends them, http POSTs them to a mail API (not in the Go aprond), log writes them to the server log (development only; refused with --public-url or --tls.domain)"),
            spec!("link-url", Str, email.link_url, [], [], "Page that sign-in links in emails open, such as https://chat.example/, with a sign-in token in its fragment (default: --public-url; empty sends codes without links)"),
            spec!("from", Str, email.from, [], [], "Sender address of sign-in emails, for --email.sender smtp or http"),
            spec!("smtp-addr", Str, email.smtp_addr, [], [], "SMTP relay as host:port, for --email.sender smtp: STARTTLS is required (such as :587), or TLS from the start on port 465"),
            spec!("smtp-user", Str, email.smtp_user, [], [], "SMTP user name; empty sends without authentication"),
            spec!("smtp-password", Str, email.smtp_password, [], [], "SMTP password"),
            spec!("smtp-insecure", Bool, email.smtp_insecure, [], [], "Send through a relay that does not offer STARTTLS, in cleartext (a relay on the same host only)"),
            spec!("http-url", Str, email.http_url, [], [], "Mail API that --email.sender http POSTs {\"from\", \"to\", \"subject\", \"text\"} to as JSON, such as https://api.cloudflare.com/client/v4/accounts/<account ID>/email/sending/send (not in the Go aprond)"),
            spec!("http-header", List, email.http_headers, [], [], "Header of each --email.sender http request, as Name: value, such as \"Authorization: Bearer <token>\"; repeat for more (not in the Go aprond)"),
        ],
    },
    Group {
        name: "Push",
        namespace: "push",
        options: &[
            spec!("disable", Bool, push.disable, [], [], "Do not offer push registration"),
            spec!("allow-insecure", Bool, push.allow_insecure, [], [], "Accept http push endpoints and ones on internal addresses, so any client can make the server POST into its network (tests only; refused with --public-url or --tls.domain)"),
            spec!("hosts", List, push.hosts, [], [], "Push service an endpoint may name, for relay and webpush alike: a host name, a *.host suffix, or a standalone * for any; repeat for more (default: fcm.googleapis.com, *.push.services.mozilla.com, web.push.apple.com, *.push.apple.com and *.notify.windows.com; not in the Go aprond)"),
            spec!("delay", Str, push.delay, ["30s"], [], "How long a message's push waits, so a user back at their screen by then is not pushed, from 0 (at once) to 60s (not in the Go aprond)"),
            spec!("vapid-private-key", Str, push.vapid_private_key, [], [], "Web Push VAPID private key, the P-256 scalar in base64url as web-push tools print it (default: one generated at the first start and kept in the store)"),
            spec!("vapid-subject", Str, push.vapid_subject, [], [], "Contact push services may use, a mailto: or https: URL, sent with Web Push (default: --public-url)"),
        ],
    },
    Group {
        name: "TLS",
        namespace: "tls",
        options: &[
            spec!("domain", List, tls.domains, [], [], "Serve HTTPS with Let's Encrypt certificates for this domain; repeat for more. Replaces --addr with --tls.addr"),
            spec!("addr", Str, tls.addr, [":443"], [], "HTTPS listen address when --tls.domain is set"),
            spec!("http-addr", Str, tls.http_addr, [":80"], [], "HTTP listen address for ACME challenges and redirects to HTTPS when --tls.domain is set"),
            spec!("cache-dir", Str, tls.cache_dir, [], [], "Directory caching certificates (default: aprond/autocert in the user cache directory)"),
            spec!("email", Str, tls.email, [], [], "Contact email given to Let's Encrypt"),
        ],
    },
    Group {
        name: "Apple",
        namespace: "apple",
        options: &[
            spec!("app-id", List, apple.app_ids, [], [], "iOS app allowed to use this server's passkeys, as <team ID>.<bundle ID>, listed in /.well-known/apple-app-site-association; repeat for more (not in the Go aprond)"),
        ],
    },
    Group {
        name: "Link previews",
        namespace: "unfurl",
        options: &[
            spec!("enable", Bool, unfurl.enable, [], [], "Fetch the pages that messages link to and attach their OpenGraph previews, with images hosted here; the server then requests any public http(s) URL a user posts (off by default; not in the Go aprond)"),
        ],
    },
    Group {
        name: "Guests",
        namespace: "guest",
        options: &[
            spec!("posting", Bool, guest.posting, [], [], "Let guests post, react, join, leave, and make rooms; without it they only read, and server.ext.settings says so (not in the Go aprond)"),
        ],
    },
    Group {
        name: "History",
        namespace: "history",
        options: &[
            spec!("retention", Str, history.retention, [], [], "Delete messages, reactions, and their uploads older than this, such as 168h, checking hourly; emptied threads and private rooms go, other rooms stay (default: keep forever; not in the Go aprond)"),
        ],
    },
    Group {
        name: "Frames",
        namespace: "frame",
        options: &[
            spec!("max-bytes", Int, frame.max_bytes, ["16384"], [], "Largest WebSocket message a client may send, in bytes; a larger one closes the connection with 1009 (not in the Go aprond)"),
            spec!("max-text-bytes", Int, frame.max_text_bytes, ["4096"], [], "Largest body.text of a message or command, in bytes (not in the Go aprond)"),
            spec!("max-depth", Int, frame.max_depth, ["8"], [], "Deepest nesting of objects and arrays in a frame, the frame itself at depth 1 (not in the Go aprond)"),
            spec!("max-nodes", Int, frame.max_nodes, ["2048"], [], "Most JSON values in a frame, object keys not counted (not in the Go aprond)"),
            spec!("max-id-bytes", Int, frame.max_id_bytes, ["128"], [], "Longest request id, in bytes (not in the Go aprond)"),
        ],
    },
    Group {
        name: "Server",
        namespace: "server",
        options: &[
            spec!("title", Str, server.title, [], [], "Plain name clients show for this server, as server.title, unless an admin's /server title sets one (default: none, so clients show the server's address; not in the Go aprond)"),
            spec!("description", Str, server.description, [], [], "CommonMark of at most 500 bytes saying what this server is about, as server.description, unless an admin's /server description sets one (default: general's description; not in the Go aprond)"),
            spec!("avatar", Str, server.avatar, [], [], "Server icon, as server.avatar: an https: URL or a small data:image/{png,jpeg,gif,webp};base64, URL, unless an admin's /server avatar sets one (not in the Go aprond)"),
        ],
    },
];

const HELP_DESCRIPTION: &str = "Show this help message";

/// Long names with their namespace, such as `upload.max-mb`.
pub fn long_name(group: &Group, spec: &Spec) -> String {
    if group.namespace.is_empty() {
        spec.long.to_string()
    } else {
        format!("{}.{}", group.namespace, spec.long)
    }
}

fn specs() -> impl Iterator<Item = (&'static Group, &'static Spec)> {
    GROUPS
        .iter()
        .flat_map(|g| g.options.iter().map(move |s| (g, s)))
}

impl Spec {
    fn can_argument(&self, options: &Options) -> bool {
        !matches!((self.get)(options), Field::Bool(_))
    }

    fn is_signed_number(&self, options: &Options) -> bool {
        matches!((self.get)(options), Field::Int(_) | Field::Int64(_))
    }
}

/// go-flags' `ErrorType`, for the kinds this parser produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    ExpectedArgument,
    UnknownFlag,
    Marshal,
    Help,
    NoArgumentForBool,
    InvalidChoice,
}

/// go-flags' `*flags.Error`. For [`ErrorKind::Help`] the message is the help
/// text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlagError {
    pub kind: ErrorKind,
    pub message: String,
}

impl std::fmt::Display for FlagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FlagError {}

fn flag_error(kind: ErrorKind, message: String) -> FlagError {
    FlagError { kind, message }
}

/// The error of an option's `Set`: go-flags' own errors, or a conversion
/// error that its callers wrap differently.
#[derive(Debug)]
pub enum SetError {
    Flag(FlagError),
    Convert(String),
}

/// Per-option state go-flags keeps on `*Option`.
#[derive(Clone, Copy, Default)]
struct State {
    /// Go's `preventDefault`: set by the command line.
    set_on_command_line: bool,
    clear_reference_before_set: bool,
}

/// go-flags' `*flags.Parser` over [`Options`].
pub struct Parser {
    /// The program name in the usage line, `path.Base(os.Args[0])`.
    pub name: String,
    pub options: Options,
    state: Vec<State>,
    default_literals: Vec<String>,
}

enum Target {
    Option(usize),
    Help,
}

impl Parser {
    pub fn new(name: &str, options: Options) -> Parser {
        let count = specs().count();
        Parser {
            name: name.to_string(),
            options,
            state: vec![State::default(); count],
            default_literals: vec![String::new(); count],
        }
    }

    /// go-flags' `FindOptionByLongName`: the option's index.
    pub fn find(&self, name: &str) -> Option<usize> {
        specs().position(|(g, s)| long_name(g, s) == name)
    }

    pub fn spec(&self, index: usize) -> (&'static Group, &'static Spec) {
        specs().nth(index).expect("option index in range")
    }

    /// Go's `option.IsSet() && !option.IsSetDefault()` after parsing.
    pub fn set_on_command_line(&self, index: usize) -> bool {
        self.state[index].set_on_command_line
    }

    /// go-flags' `Parser.ParseArgs`: parses `args` into the options and
    /// returns the arguments that are not options.
    pub fn parse_args<S: AsRef<str>>(&mut self, args: &[S]) -> Result<Vec<String>, FlagError> {
        for (i, (_, spec)) in specs().enumerate() {
            self.state[i].clear_reference_before_set = true;
            self.default_literals[i] = default_literal(spec, &self.options);
        }
        let mut args: std::collections::VecDeque<String> =
            args.iter().map(|a| a.as_ref().to_string()).collect();
        let mut rest = Vec::new();
        while let Some(arg) = args.pop_front() {
            if arg == "--" {
                rest.extend(args.drain(..));
                break;
            }
            if !argument_is_option(&arg) {
                rest.push(arg);
                continue;
            }
            let (name, is_long) = match arg.strip_prefix("--") {
                Some(name) => (name, true),
                None => (&arg[1..], false),
            };
            let (name, argument) = match name.find('=') {
                Some(pos) if is_long || pos == 1 => {
                    (&name[..pos], Some(name[pos + 1..].to_string()))
                }
                _ => (name, None),
            };
            if is_long {
                let target = if name == "help" {
                    Target::Help
                } else {
                    match self.find(name) {
                        Some(i) => Target::Option(i),
                        None => {
                            return Err(flag_error(
                                ErrorKind::UnknownFlag,
                                format!("unknown flag `{name}'"),
                            ))
                        }
                    }
                };
                self.parse_option(&mut args, target, argument)?;
            } else {
                // The only short option is -h, which takes no argument, so
                // go-flags' splitShortConcatArg never splits.
                let mut argument = argument;
                for c in name.chars() {
                    if c != 'h' {
                        return Err(flag_error(
                            ErrorKind::UnknownFlag,
                            format!("unknown flag `{c}'"),
                        ));
                    }
                    self.parse_option(&mut args, Target::Help, argument.take())?;
                }
            }
        }
        for i in 0..self.state.len() {
            if self.state[i].set_on_command_line {
                continue;
            }
            let (_, spec) = self.spec(i);
            if !spec.defaults.is_empty() {
                empty((spec.get_mut)(&mut self.options));
                for d in spec.defaults {
                    self.set(i, Some(d)).map_err(|e| self.marshal_error(i, e))?;
                }
                self.state[i].set_on_command_line = false;
            }
        }
        Ok(rest)
    }

    fn parse_option(
        &mut self,
        args: &mut std::collections::VecDeque<String>,
        target: Target,
        argument: Option<String>,
    ) -> Result<(), FlagError> {
        let index = match target {
            Target::Help => {
                if argument.is_some() {
                    return Err(flag_error(
                        ErrorKind::NoArgumentForBool,
                        "bool flag `-h, --help' cannot have an argument".to_string(),
                    ));
                }
                return Err(flag_error(ErrorKind::Help, self.write_help()));
            }
            Target::Option(i) => i,
        };
        let (group, spec) = self.spec(index);
        let flag = format!("--{}", long_name(group, spec));
        if !spec.can_argument(&self.options) {
            if argument.is_some() {
                return Err(flag_error(
                    ErrorKind::NoArgumentForBool,
                    format!("bool flag `{flag}' cannot have an argument"),
                ));
            }
            return self
                .set(index, None)
                .map_err(|e| self.marshal_error(index, e));
        }
        let arg = match argument {
            Some(arg) => arg,
            None => {
                let Some(arg) = args.pop_front() else {
                    return Err(flag_error(
                        ErrorKind::ExpectedArgument,
                        format!("expected argument for flag `{flag}'"),
                    ));
                };
                let signed_number = spec.is_signed_number(&self.options)
                    && arg.len() > 1
                    && arg.as_bytes()[1].is_ascii_digit();
                if argument_is_option(&arg) && !signed_number {
                    return Err(flag_error(
                        ErrorKind::ExpectedArgument,
                        format!("expected argument for flag `{flag}', but got option `{arg}'"),
                    ));
                }
                if arg == "--" {
                    return Err(flag_error(
                        ErrorKind::ExpectedArgument,
                        format!("expected argument for flag `{flag}', but got double dash `--'"),
                    ));
                }
                arg
            }
        };
        let arg = if arg.starts_with('"') {
            match strconv::unquote(&arg) {
                Ok(unquoted) => String::from_utf8_lossy(&unquoted).into_owned(),
                Err(e) => return Err(self.marshal_error(index, SetError::Convert(e.to_string()))),
            }
        } else {
            arg
        };
        self.set(index, Some(&arg))
            .map_err(|e| self.marshal_error(index, e))
    }

    /// go-flags' `marshalError`: a conversion error, with the flag and its
    /// expected Go type.
    fn marshal_error(&self, index: usize, err: SetError) -> FlagError {
        match err {
            SetError::Flag(e) => e,
            SetError::Convert(text) => {
                let (group, spec) = self.spec(index);
                let expected = match (spec.get)(&self.options) {
                    Field::Str(_) => "string",
                    Field::Bool(_) => "bool",
                    Field::Int(_) => "int",
                    Field::Int64(_) => "int64",
                    Field::List(_) => "[]string",
                };
                flag_error(
                    ErrorKind::Marshal,
                    format!(
                        "invalid argument for flag `--{}' (expected {expected}): {text}",
                        long_name(group, spec)
                    ),
                )
            }
        }
    }

    /// go-flags' `Option.Set`. A `None` value sets a bool to true.
    pub fn set(&mut self, index: usize, value: Option<&str>) -> Result<(), SetError> {
        let (group, spec) = self.spec(index);
        let state = &mut self.state[index];
        let clear = state.clear_reference_before_set;
        state.set_on_command_line = true;
        state.clear_reference_before_set = false;
        if clear {
            if let FieldMut::List(list) = (spec.get_mut)(&mut self.options) {
                list.clear();
            }
        }
        if !spec.choices.is_empty() {
            let value = value.unwrap_or_default();
            if !spec.choices.contains(&value) {
                let (last, init) = spec.choices.split_last().expect("choices not empty");
                let mut allowed = init.join(", ");
                if spec.choices.len() > 1 {
                    allowed += " or ";
                    allowed += last;
                }
                return Err(SetError::Flag(flag_error(
                    ErrorKind::InvalidChoice,
                    format!(
                        "Invalid value `{value}' for option `--{}'. Allowed values are: {allowed}",
                        long_name(group, spec)
                    ),
                )));
            }
        }
        let value = value.unwrap_or_default();
        match (spec.get_mut)(&mut self.options) {
            FieldMut::Str(s) => *s = value.to_string(),
            FieldMut::Bool(b) => {
                *b = value.is_empty()
                    || strconv::parse_bool(value).map_err(|e| SetError::Convert(e.to_string()))?
            }
            FieldMut::Int(n) | FieldMut::Int64(n) => {
                *n = strconv::parse_int(value, 0, 64)
                    .map_err(|e| SetError::Convert(e.to_string()))?
            }
            FieldMut::List(list) => list.push(value.to_string()),
        }
        Ok(())
    }

    /// Marks an option as not given on the command line, after
    /// [`Parser::set`] applies a value from elsewhere.
    pub(crate) fn clear_command_line_mark(&mut self, index: usize) {
        self.state[index].set_on_command_line = false;
    }

    /// go-flags' `Parser.WriteHelp`, with the 80 columns it uses when
    /// standard input is not a terminal.
    pub fn write_help(&self) -> String {
        const COLUMNS: usize = 80;
        let mut max_long_len = HELP_LONG.len();
        for (g, s) in specs() {
            let mut l = long_name(g, s).chars().count();
            if !s.choices.is_empty() {
                l += format!("[{}]", s.choices.join("|")).chars().count();
            }
            max_long_len = max_long_len.max(l);
        }
        // go-flags' descriptionStart with a short option (-h) present.
        let desc_start = max_long_len + 2 + 2 + 4 + 2;
        let mut out = format!("Usage:\n  {} [OPTIONS]\n", self.name);
        let write_option = |out: &mut String,
                            short: bool,
                            long: &str,
                            arg: Option<&str>,
                            description: &str,
                            default: &str| {
            let mut line = String::from("  ");
            line += if short { "-h, " } else { "    " };
            line += "--";
            line += long;
            if let Some(arg) = arg {
                line += "=";
                line += arg;
            }
            let written = line.len();
            out.push_str(&line);
            out.push_str(&" ".repeat(desc_start.saturating_sub(written)));
            let description = if default.is_empty() {
                description.to_string()
            } else {
                format!("{description} (default: {default})")
            };
            out.push_str(&wrap_text(
                &description,
                COLUMNS - desc_start,
                &" ".repeat(desc_start),
            ));
            out.push('\n');
        };
        let mut index = 0;
        for group in GROUPS {
            out.push_str(&format!("\n{}:\n", group.name));
            for spec in group.options {
                let choices = if spec.choices.is_empty() {
                    String::new()
                } else {
                    format!("[{}]", spec.choices.join("|"))
                };
                let arg = spec.can_argument(&self.options).then_some(choices.as_str());
                write_option(
                    &mut out,
                    false,
                    &long_name(group, spec),
                    arg,
                    spec.description,
                    &self.default_literals[index],
                );
                index += 1;
            }
        }
        out.push_str("\nHelp Options:\n");
        write_option(&mut out, true, HELP_LONG, None, HELP_DESCRIPTION, "");
        out
    }
}

const HELP_LONG: &str = "help";

fn empty(field: FieldMut<'_>) {
    match field {
        FieldMut::Str(s) => s.clear(),
        FieldMut::Bool(b) => *b = false,
        FieldMut::Int(n) | FieldMut::Int64(n) => *n = 0,
        FieldMut::List(l) => l.clear(),
    }
}

/// go-flags' `updateDefaultLiteral`: the `default` tags, or else the value
/// the field holds before parsing.
fn default_literal(spec: &Spec, options: &Options) -> String {
    if !spec.defaults.is_empty() {
        return spec
            .defaults
            .iter()
            .map(|d| quote_if_needed(d))
            .collect::<Vec<_>>()
            .join(", ");
    }
    match (spec.get)(options) {
        Field::Bool(_) => String::new(),
        Field::Str(s) => s.clone(),
        Field::Int(n) | Field::Int64(n) if *n != 0 => n.to_string(),
        Field::Int(_) | Field::Int64(_) => String::new(),
        Field::List(l) if l.is_empty() => String::new(),
        Field::List(l) => format!("[{}]", l.join(", ")),
    }
}

fn quote_if_needed(s: &str) -> String {
    if s.chars().all(strconv::is_print) {
        s.to_string()
    } else {
        strconv::quote(s)
    }
}

/// go-flags' `argumentIsOption` on Unix.
fn argument_is_option(arg: &str) -> bool {
    let b = arg.as_bytes();
    (b.len() > 1 && b[0] == b'-' && b[1] != b'-')
        || (b.len() > 2 && b[0] == b'-' && b[1] == b'-' && b[2] != b'-')
}

/// go-flags' `wrapText`, byte for byte, including its hyphenated break of a
/// word longer than the line.
pub fn wrap_text(s: &str, l: usize, prefix: &str) -> String {
    let l = l.max(10);
    let mut ret: Vec<u8> = Vec::new();
    for line in s.split('\n') {
        let mut retline: Vec<u8> = Vec::new();
        let mut line = line.trim().as_bytes().to_vec();
        while line.len() > l {
            let mut suffix: &[u8] = b"";
            let pos = match line[..l].iter().rposition(|&c| c == b' ') {
                Some(pos) => pos,
                None => {
                    suffix = b"-\n";
                    l - 1
                }
            };
            if !retline.is_empty() {
                retline.push(b'\n');
                retline.extend_from_slice(prefix.as_bytes());
            }
            retline.extend_from_slice(trim_bytes(&line[..pos]));
            retline.extend_from_slice(suffix);
            line = trim_bytes(&line[pos..]).to_vec();
        }
        if !line.is_empty() {
            if !retline.is_empty() {
                retline.push(b'\n');
                retline.extend_from_slice(prefix.as_bytes());
            }
            retline.extend_from_slice(&line);
        }
        if !ret.is_empty() {
            ret.push(b'\n');
            if !retline.is_empty() {
                ret.extend_from_slice(prefix.as_bytes());
            }
        }
        ret.extend_from_slice(&retline);
    }
    String::from_utf8_lossy(&ret).into_owned()
}

fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |e| e + 1);
    &b[start..end]
}
