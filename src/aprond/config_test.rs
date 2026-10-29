//! cmd/aprond/config_test.go, plus go-flags behavior and byte comparisons of
//! `--help` and `--print-config` against the Go `aprond`.

use super::config::{load_config, print_config};
use super::options::{ErrorKind, Options, Parser};
use super::settings::{server_settings, EmailSender};
use std::collections::BTreeMap;

fn parse(args: &[&str]) -> Parser {
    let mut parser = Parser::new("aprond", Options::default());
    if let Err(e) = parser.parse_args(args) {
        panic!("{e}");
    }
    parser
}

fn write_config(text: &str) -> (tempdir::Dir, String) {
    let dir = tempdir::Dir::new();
    let path = format!("{}/aprond.toml", dir.path());
    std::fs::write(&path, text).unwrap();
    (dir, path)
}

mod tempdir {
    pub struct Dir(String);

    impl Dir {
        pub fn new() -> Dir {
            Dir(rust_stdlib::os::mkdir_temp("", "aprond-test").unwrap())
        }
        pub fn path(&self) -> &str {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn test_config_file_sets_options_the_command_line_does_not() {
    let (_dir, path) = write_config(
        r#"
addr = "0.0.0.0:9000"
public-url = "https://chat.example"
messages-per-minute = 30

[webauthn]
rp-id = "chat.example"
origin = ["https://chat.example"]

[upload]
max-mb = 5
"#,
    );
    let mut parser = parse(&["--addr", "127.0.0.1:9999", "--upload.max-mb", "7"]);
    load_config(&mut parser, &path).unwrap();
    let options = &parser.options;
    assert!(
        options.addr == "127.0.0.1:9999" && options.upload.max_mb == 7,
        "command line overridden: addr {:?}, max-mb {}",
        options.addr,
        options.upload.max_mb
    );
    assert!(
        options.public_url == "https://chat.example"
            && options.messages_per_minute == 30
            && options.webauthn.rp_id == "chat.example",
        "file settings not applied: {options:?}"
    );
    assert_eq!(
        options.webauthn.origins,
        ["https://chat.example"],
        "a list replaces its default"
    );
    assert_eq!(options.upload.max_message_mb, 20, "unset default changed");
}

#[test]
fn test_config_file_rejects_unknown_settings() {
    for text in [
        r#"adress = ":80""#,
        "[upload]\nmax = 1",
        r#"config = "other.toml""#,
        r#"max-connections = "many""#,
    ] {
        let mut parser = parse(&[]);
        let (_dir, path) = write_config(text);
        assert!(
            load_config(&mut parser, &path).is_err(),
            "accepted {text:?}"
        );
    }
}

#[test]
fn test_config_file_errors_are_gos() {
    for (text, want) in [
        (r#"adress = ":80""#, r#"unknown setting "adress""#),
        ("[upload]\nmax = 1", r#"unknown setting "upload.max""#),
        (r#"config = "other.toml""#, r#"unknown setting "config""#),
        (
            r#"max-connections = "many""#,
            r#"setting "max-connections": strconv.ParseInt: parsing "many": invalid syntax"#,
        ),
        (
            "[email]\nsender = \"mail\"",
            "setting \"email.sender\": Invalid value `mail' for option `--email.sender'. Allowed values are: smtp, http or log",
        ),
    ] {
        let mut parser = parse(&[]);
        let (_dir, path) = write_config(text);
        assert_eq!(load_config(&mut parser, &path).unwrap_err(), want);
    }
}

#[test]
fn test_config_values_go_through_fmt_sprint() {
    let (_dir, path) = write_config("addr = 9000\n[upload]\nmax-mb = 5.0\n[email]\nenable = 1\n");
    let mut parser = parse(&[]);
    load_config(&mut parser, &path).unwrap();
    assert_eq!(parser.options.addr, "9000");
    assert_eq!(parser.options.upload.max_mb, 5);
    assert!(parser.options.email.enable);
}

#[test]
fn test_printed_config_loads_back() {
    let parser = parse(&[
        "--origin",
        "https://a.example",
        "--origin",
        "https://b.example",
        "--push.disable",
        "--tls.domain",
        "chat.example",
    ]);
    let printed = print_config(&parser);
    assert!(
        printed.contains("[upload]") && !printed.contains("print-config"),
        "printed config:\n{printed}"
    );
    let mut fresh = parse(&[]);
    let (_dir, path) = write_config(&printed);
    if let Err(e) = load_config(&mut fresh, &path) {
        panic!("{e} in:\n{printed}");
    }
    assert_eq!(fresh.options, parser.options, "round trip");
}

#[test]
fn test_tls_domain_is_the_public_url() {
    let parser = parse(&["--tls.domain", "chat.example", "--webauthn.rp-id", ""]);
    let config = server_settings(&parser.options).unwrap();
    assert!(
        config.public_url == "https://chat.example" && config.webauthn.is_none(),
        "config: public URL {:?}, passkeys {}",
        config.public_url,
        config.webauthn.is_some()
    );
}

#[test]
fn test_vapid_settings() {
    let parser = parse(&[
        "--push.vapid-private-key",
        "key",
        "--push.vapid-subject",
        "mailto:ops@chat.example",
    ]);
    let config = server_settings(&parser.options).unwrap();
    assert!(
        config.vapid_private_key == "key" && config.vapid_subject == "mailto:ops@chat.example",
        "VAPID settings: {:?} {:?}",
        config.vapid_private_key,
        config.vapid_subject
    );
    for subject in ["ops@chat.example", "http://chat.example"] {
        let parser = parse(&["--push.vapid-subject", subject]);
        assert!(
            server_settings(&parser.options).is_err(),
            "VAPID subject {subject:?} accepted"
        );
    }
}

#[test]
fn test_insecure_push_is_for_tests_only() {
    let parser = parse(&["--push.allow-insecure"]);
    match server_settings(&parser.options) {
        Ok(config) => assert!(config.allow_insecure_push, "allow insecure false"),
        Err(e) => panic!("error {e}"),
    }
    // A public server refuses it, as it lets clients reach internal addresses.
    for args in [
        [
            "--push.allow-insecure",
            "--public-url",
            "https://chat.example",
        ],
        ["--push.allow-insecure", "--tls.domain", "chat.example"],
    ] {
        let parser = parse(&args);
        assert!(
            server_settings(&parser.options).is_err(),
            "accepted {args:?}"
        );
    }
}

#[test]
fn test_welcome_and_roles() {
    let parser = parse(&[
        "--welcome",
        "Sign in with **email**.",
        "--role",
        "admin=ada",
        "--role",
        "Moderator = bob",
        "--role",
        "admin=carol",
    ]);
    let config = server_settings(&parser.options).unwrap();
    assert_eq!(config.welcome, "Sign in with **email**.", "welcome");
    let want = BTreeMap::from([
        (
            "admin".to_string(),
            vec!["ada".to_string(), "carol".to_string()],
        ),
        ("mod".to_string(), vec!["bob".to_string()]),
    ]);
    assert_eq!(config.roles, want, "roles");
    for grant in ["admin", "=ada", "admin=", "9lives=ada", "a b=ada"] {
        let parser = parse(&["--role", grant]);
        assert!(
            server_settings(&parser.options).is_err(),
            "accepted --role {grant:?}"
        );
    }
}

#[test]
fn test_email_senders() {
    // Email sign-in is off unless --email.enable is set, whatever the sender.
    for args in [
        &[][..],
        &["--email.sender", "log"][..],
        &[
            "--email.sender",
            "smtp",
            "--email.smtp-addr",
            "smtp.example:587",
            "--email.from",
            "chat@example.com",
        ][..],
    ] {
        let parser = parse(args);
        let config = server_settings(&parser.options).unwrap();
        assert!(
            config.email_sender.is_none(),
            "email sender {:?} without --email.enable: {args:?}",
            config.email_sender
        );
    }
    let parser = parse(&["--email.enable", "--email.sender", "log"]);
    let config = server_settings(&parser.options).unwrap();
    assert!(
        matches!(config.email_sender, Some(EmailSender::Log)) && config.email_link_url.is_empty(),
        "log sender {:?}, link {:?}",
        config.email_sender,
        config.email_link_url
    );
    // The log sender is for development: a public server refuses it.
    for args in [
        [
            "--email.enable",
            "--email.sender",
            "log",
            "--public-url",
            "https://chat.example",
        ],
        [
            "--email.enable",
            "--email.sender",
            "log",
            "--tls.domain",
            "chat.example",
        ],
    ] {
        let parser = parse(&args);
        assert!(
            server_settings(&parser.options).is_err(),
            "accepted {args:?}"
        );
    }
    // smtp is the default sender.
    let parser = parse(&[
        "--email.enable",
        "--email.smtp-addr",
        "smtp.example:587",
        "--email.from",
        "Apron <chat@example.com>",
        "--public-url",
        "https://chat.example/",
    ]);
    let config = server_settings(&parser.options).unwrap();
    match &config.email_sender {
        Some(EmailSender::Smtp(sender))
            if sender.addr == "smtp.example:587"
                && !sender.insecure
                && config.email_link_url == "https://chat.example/" => {}
        other => panic!("smtp sender {other:?}, link {:?}", config.email_link_url),
    }
    for args in [
        ["--email.enable", "--email.from", "chat@example.com"],
        ["--email.enable", "--email.smtp-addr", "smtp.example:587"],
    ] {
        let parser = parse(&args);
        assert!(
            server_settings(&parser.options).is_err(),
            "accepted {args:?}"
        );
    }
    // http POSTs to a mail API with the given headers.
    let parser = parse(&[
        "--email.enable",
        "--email.sender",
        "http",
        "--email.http-url",
        "https://api.example/send",
        "--email.from",
        "chat@example.com",
        "--email.http-header",
        "Authorization: Bearer secret",
    ]);
    let config = server_settings(&parser.options).unwrap();
    match &config.email_sender {
        Some(EmailSender::Http(sender))
            if sender.url == "https://api.example/send"
                && sender.from == "<chat@example.com>"
                && sender.headers
                    == [("Authorization".to_string(), "Bearer secret".to_string())] => {}
        other => panic!("http sender {other:?}"),
    }
}

#[test]
fn test_flag_errors_are_go_flags() {
    for (args, kind, want) in [
        (&["--bogus"][..], ErrorKind::UnknownFlag, "unknown flag `bogus'"),
        (&["-x"][..], ErrorKind::UnknownFlag, "unknown flag `x'"),
        (&["--addr"][..], ErrorKind::ExpectedArgument, "expected argument for flag `--addr'"),
        (
            &["--addr", "--store", "memory"][..],
            ErrorKind::ExpectedArgument,
            "expected argument for flag `--addr', but got option `--store'",
        ),
        (
            &["--addr", "--"][..],
            ErrorKind::ExpectedArgument,
            "expected argument for flag `--addr', but got double dash `--'",
        ),
        (
            &["--max-connections", "many"][..],
            ErrorKind::Marshal,
            "invalid argument for flag `--max-connections' (expected int): strconv.ParseInt: parsing \"many\": invalid syntax",
        ),
        (
            &["--upload.max-mb=x"][..],
            ErrorKind::Marshal,
            "invalid argument for flag `--upload.max-mb' (expected int64): strconv.ParseInt: parsing \"x\": invalid syntax",
        ),
        (
            &["--push.disable=true"][..],
            ErrorKind::NoArgumentForBool,
            "bool flag `--push.disable' cannot have an argument",
        ),
        (
            &["--email.sender", "mail"][..],
            ErrorKind::InvalidChoice,
            "Invalid value `mail' for option `--email.sender'. Allowed values are: smtp, http or log",
        ),
        (
            &["--help=1"][..],
            ErrorKind::NoArgumentForBool,
            "bool flag `-h, --help' cannot have an argument",
        ),
    ] {
        let mut parser = Parser::new("aprond", Options::default());
        let err = parser.parse_args(args).unwrap_err();
        assert_eq!((err.kind, err.message.as_str()), (kind, want), "{args:?}");
    }
}

#[test]
fn test_flag_syntax() {
    let parser = parse(&[
        "serve",
        "--addr=:9000",
        "--max-connections",
        "-5",
        "--welcome",
        "\"quoted\\tvalue\"",
        "--webauthn.origin",
        "https://a",
        "--webauthn.origin=https://b",
        "--",
        "--bogus",
    ]);
    assert_eq!(parser.options.addr, ":9000");
    assert_eq!(parser.options.max_connections, -5);
    assert_eq!(parser.options.welcome, "quoted\tvalue");
    assert_eq!(parser.options.webauthn.origins, ["https://a", "https://b"]);
    assert_eq!(parser.options.max_listed_members, 1000);
    assert_eq!(parser.options.email.sender, "smtp");
    assert_eq!(parser.options.tls.addr, ":443");
}

/// apron-server-cloudflare's `SERVER_*` variables, as `--server.*`: each
/// trimmed, empty left out, and checked as `/server` checks it.
#[test]
fn test_server_metadata_flags() {
    use crate::server::metadata::ServerMetadata;
    let config = server_settings(&parse(&[]).options).unwrap();
    assert_eq!(config.server, ServerMetadata::default());
    let parser = parse(&[
        "--server.title",
        " Chat Club ",
        "--server.description",
        "Talk about *clubs*.\nAll welcome.",
        "--server.avatar",
        "https://chat.example/icon.png",
    ]);
    assert_eq!(
        server_settings(&parser.options).unwrap().server,
        ServerMetadata {
            title: "Chat Club".into(),
            description: "Talk about *clubs*.\nAll welcome.".into(),
            avatar: "https://chat.example/icon.png".into(),
        }
    );
    let parser = parse(&["--server.description", "   "]);
    assert_eq!(
        server_settings(&parser.options).unwrap().server,
        ServerMetadata::default()
    );
    let data = "data:image/png;base64,iVBORw0KGgo=";
    let parser = parse(&["--server.avatar", data]);
    assert_eq!(
        server_settings(&parser.options).unwrap().server.avatar,
        data
    );
    let long_title = "x".repeat(65);
    let long_description = "x".repeat(501);
    for (flag, value) in [
        ("--server.title", long_title.as_str()),
        ("--server.title", "two\nlines"),
        ("--server.description", long_description.as_str()),
        ("--server.description", "a\u{7}b"),
        ("--server.avatar", "http://chat.example/icon.png"),
        ("--server.avatar", "data:image/svg+xml;base64,PHN2Zz4="),
    ] {
        let parser = parse(&[flag, value]);
        assert!(
            server_settings(&parser.options).is_err(),
            "accepted {flag} {value:?}"
        );
    }
    let parser = parse(&["--server.title", &"x".repeat(64)]);
    assert!(server_settings(&parser.options).is_ok(), "64 characters");
    let parser = parse(&["--server.description", &"x".repeat(500)]);
    assert!(server_settings(&parser.options).is_ok(), "500 bytes");
}
