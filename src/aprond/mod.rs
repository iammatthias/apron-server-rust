//! cmd/aprond outside the server: flags and TOML, the checks of
//! `serverConfig`, the SMTP sender, the listener limit, the debug listener,
//! and ACME certificates. The binary wires these to `server`.

pub mod acme;
pub mod config;
pub mod debug;
pub mod email;
pub mod listener;
pub mod options;
pub mod settings;

#[cfg(test)]
mod config_test;
#[cfg(test)]
mod email_test;

use options::{ErrorKind, Options, Parser};
use rust_stdlib::path::filepath;
use std::io::Write;

/// The options main() sets before parsing: the defaults that depend on the
/// user's directories.
pub fn initial_options() -> Options {
    let data = user_data_dir();
    Options {
        store: format!("sqlite:{}", filepath::join(&[data.as_str(), "aprond.db"])),
        upload: options::UploadOptions {
            dir: filepath::join(&[data.as_str(), "uploads"]),
            ..Default::default()
        },
        tls: options::TlsOptions {
            cache_dir: user_cache_dir("autocert"),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The part of Go's main() before `run`: parses `args` (without the program
/// name), loads `--config`, and handles `--help` and `--print-config`.
/// `Err` carries the exit status, after the output Go prints.
pub fn command_line<S: AsRef<str>>(program: &str, args: &[S]) -> Result<Options, i32> {
    command_line_to(
        program,
        args,
        initial_options(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}

/// [`command_line`] from the given initial options, writing to `stdout` and
/// `stderr`.
pub fn command_line_to<S: AsRef<str>>(
    program: &str,
    args: &[S],
    initial: Options,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<Options, i32> {
    let name = filepath::base(program);
    let mut parser = Parser::new(name, initial);
    if let Err(e) = parser.parse_args(args) {
        // go-flags' PrintErrors: help to standard output, errors to standard
        // error, each with a newline.
        if e.kind == ErrorKind::Help {
            let _ = writeln!(stdout, "{}", e.message);
            return Err(0);
        }
        let _ = writeln!(stderr, "{}", e.message);
        return Err(1);
    }
    if !parser.options.config.is_empty() {
        let path = parser.options.config.clone();
        if let Err(e) = config::load_config(&mut parser, &path) {
            let _ = writeln!(stderr, "Failed to load {path}: {e}");
            return Err(1);
        }
    }
    if parser.options.print_config {
        let printed = config::print_config(&parser);
        if let Err(e) = stdout
            .write_all(printed.as_bytes())
            .and_then(|_| stdout.flush())
        {
            let _ = writeln!(stderr, "{e}");
            return Err(1);
        }
        return Err(0);
    }
    Ok(parser.options)
}

/// aprond in the user's data directory: `$XDG_DATA_HOME`, usually
/// ~/.local/share, on Linux and other Unix systems, and the application data
/// directory on macOS.
pub fn user_data_dir() -> String {
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        if let Ok(dir) = rust_stdlib::os::user_config_dir() {
            return filepath::join(&[dir.as_str(), "aprond"]);
        }
    } else {
        let dir = std::env::var("XDG_DATA_HOME").unwrap_or_default();
        if filepath::is_abs(&dir) {
            return filepath::join(&[dir.as_str(), "aprond"]);
        }
        if let Ok(home) = rust_stdlib::os::user_home_dir() {
            return filepath::join(&[home.as_str(), ".local", "share", "aprond"]);
        }
    }
    "aprond".to_string()
}

/// aprond/<name> in the user's cache directory (`$XDG_CACHE_HOME`, usually
/// ~/.cache, on Linux), or empty when there is none.
pub fn user_cache_dir(name: &str) -> String {
    match rust_stdlib::os::user_cache_dir() {
        Ok(cache) => filepath::join(&[cache.as_str(), "aprond", name]),
        Err(_) => String::new(),
    }
}
