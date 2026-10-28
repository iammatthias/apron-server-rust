//! cmd/aprond/email.go: email sign-in codes through an SMTP relay.

use rust_stdlib::context::Context;
use rust_stdlib::net::{self, mail, smtp, AddrRef, Conn, NetError};
use rust_stdlib::time::{self, Time};
use rust_stdlib_tls::tls;
use std::any::Any;
use std::io::Write;
use std::sync::Arc;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Sends email sign-in codes through an SMTP relay. On port 465 it speaks TLS
/// from the start; otherwise it requires STARTTLS unless `insecure` is set.
/// It authenticates with PLAIN when a user is given. Every delivery is
/// bounded by its context's deadline, the connection included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmtpSender {
    pub addr: String,
    pub host: String,
    pub from: String,
    pub username: String,
    pub password: String,
    pub insecure: bool,
}

impl SmtpSender {
    /// Go's `newSMTPSender`.
    pub fn new(
        addr: &str,
        from: &str,
        username: &str,
        password: &str,
        insecure: bool,
    ) -> Result<SmtpSender, String> {
        let host = match net::split_host_port(addr) {
            Ok((host, _)) if !host.is_empty() => host,
            _ => {
                return Err(format!(
                    "invalid --email.smtp-addr {}: use host:port, such as smtp.example.com:587",
                    rust_stdlib::strconv::quote(addr)
                ))
            }
        };
        let parsed = match mail::parse_address(from) {
            Ok(parsed) if !from.is_empty() => parsed,
            _ => {
                return Err(format!(
                    "invalid --email.from {}: an email address is required",
                    rust_stdlib::strconv::quote(from)
                ))
            }
        };
        Ok(SmtpSender {
            addr: addr.to_string(),
            host,
            from: parsed.to_string(),
            username: username.to_string(),
            password: password.to_string(),
            insecure,
        })
    }

    /// The domain of the sender address, for Message-ID.
    fn message_domain(&self) -> String {
        match mail::parse_address(&self.from) {
            Ok(parsed) => parsed
                .address
                .split_once('@')
                .map(|(_, domain)| domain.to_string())
                .unwrap_or_default(),
            Err(_) => self.host.clone(),
        }
    }

    /// Renders a sign-in email. `text` is `server.SignInEmail.Text()`.
    pub fn message(&self, to: &str, code: &str, add: bool, text: &str) -> Vec<u8> {
        let subject = if add {
            format!("Your code to add this address is {code}")
        } else {
            format!("Your sign-in code is {code}")
        };
        let mut message = String::new();
        message += &format!("From: {}\r\n", self.from);
        message += &format!("To: {to}\r\n");
        message += &format!("Subject: {subject}\r\n");
        message += &format!("Date: {}\r\n", time::now().format(time::RFC1123Z));
        message += &format!(
            "Message-ID: <{}@{}>\r\n",
            rust_stdlib_crypto::rand::text(),
            self.message_domain()
        );
        message += "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n";
        message += &text.replace('\n', "\r\n");
        message.into_bytes()
    }

    /// Go's `SendSignInCode` for `server.SignInEmail{To: to, Code: code,
    /// Add: add}`, whose `Text()` is `text`.
    pub fn send_sign_in_code(
        &self,
        ctx: &Context,
        to: &str,
        code: &str,
        add: bool,
        text: &str,
    ) -> Result<(), Error> {
        let port = net::split_host_port(&self.addr)
            .map(|(_, port)| port)
            .unwrap_or_default();
        let implicit_tls = port == "465";
        let conn: Arc<dyn Conn> = if implicit_tls {
            let dialer = tls::Dialer {
                net_dialer: None,
                config: Some(Arc::new(self.tls_config())),
            };
            Arc::new(dialer.dial_context(ctx, "tcp", &self.addr)?)
        } else {
            Arc::from(net::Dialer::default().dial_context(ctx, "tcp", &self.addr)?)
        };
        let _close = CloseOnDrop(conn.clone());
        if let Some(deadline) = ctx.deadline() {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let _ = conn.set_deadline(&time::now().add(left.into()));
        }
        // Closing the connection when the context ends interrupts any
        // exchange still waiting on the relay.
        let closer = conn.clone();
        let stop = ctx.after_func(move || {
            let _ = closer.close();
        });
        let _stop = StopOnDrop(stop);

        let mut client = smtp::Client::new(Box::new(SharedConn(conn)), &self.host)?;
        let result = self.exchange(&mut client, implicit_tls, to, code, add, text);
        let _ = client.close();
        result
    }

    fn exchange(
        &self,
        client: &mut smtp::Client,
        implicit_tls: bool,
        to: &str,
        code: &str,
        add: bool,
        text: &str,
    ) -> Result<(), Error> {
        let (starttls, _) = client.extension("STARTTLS");
        if !implicit_tls && starttls {
            client.start_tls(&self.tls_config())?;
        } else if !implicit_tls && !self.insecure {
            return Err(
                "the SMTP relay does not offer STARTTLS; set --email.smtp-insecure to send in cleartext"
                    .into(),
            );
        }
        if !self.username.is_empty() {
            // net/smtp sends PLAIN credentials only over TLS or to localhost.
            let mut auth = smtp::plain_auth("", &self.username, &self.password, &self.host);
            client.auth(&mut auth)?;
        }
        let sender = mail::parse_address(&self.from)?;
        client.mail(&sender.address)?;
        client.rcpt(to)?;
        let mut w = client.data()?;
        w.write_all(&self.message(to, code, add, text))?;
        w.close()?;
        client.quit()?;
        Ok(())
    }

    fn tls_config(&self) -> tls::Config {
        let mut config = tls::Config::new();
        config.server_name = self.host.clone();
        config
    }
}

struct CloseOnDrop(Arc<dyn Conn>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}

struct StopOnDrop(rust_stdlib::context::StopFunc);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// One connection shared by the SMTP client and the context's closer.
struct SharedConn(Arc<dyn Conn>);

impl Conn for SharedConn {
    fn read(&self, b: &mut [u8]) -> Result<usize, NetError> {
        self.0.read(b)
    }
    fn write(&self, b: &[u8]) -> Result<usize, NetError> {
        self.0.write(b)
    }
    fn close(&self) -> Result<(), NetError> {
        self.0.close()
    }
    fn local_addr(&self) -> Option<AddrRef> {
        self.0.local_addr()
    }
    fn remote_addr(&self) -> Option<AddrRef> {
        self.0.remote_addr()
    }
    fn set_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_deadline(t)
    }
    fn set_read_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_read_deadline(t)
    }
    fn set_write_deadline(&self, t: &Time) -> Result<(), NetError> {
        self.0.set_write_deadline(t)
    }
    fn as_any(&self) -> &dyn Any {
        self.0.as_any()
    }
    fn tls_connection_state(&self) -> Option<net::TlsConnectionState> {
        self.0.tls_connection_state()
    }
    fn handshake(&self) -> Result<(), NetError> {
        self.0.handshake()
    }
}
