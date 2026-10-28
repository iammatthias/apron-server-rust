//! cmd/aprond/config.go: the TOML file behind `--config`, and
//! `--print-config` with BurntSushi/toml's encoder formatting.

use super::options::{long_name, Field, Parser, SetError, GROUPS};
use rust_stdlib::{os, strconv};

/// Options that configure how aprond runs and are not settings.
const COMMAND_ONLY: &[&str] = &["config", "print-config"];

/// Applies a TOML file's settings to options not given on the command line.
/// Top-level keys are flag names; each table is a flag group's namespace, so
/// `[upload] max-mb = 20` sets `--upload.max-mb`. A list in the file replaces
/// the option's default rather than adding to it.
pub fn load_config(parser: &mut Parser, path: &str) -> Result<(), String> {
    let data = os::read_file(path).map_err(|e| e.to_string())?;
    let text = String::from_utf8(data).map_err(|_| "toml: invalid UTF-8".to_string())?;
    let values: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| format!("toml: {}", e.message()))?;
    apply_config(parser, "", &values)
}

fn apply_config(parser: &mut Parser, namespace: &str, values: &toml::Table) -> Result<(), String> {
    // toml::Table is a BTreeMap, so keys come sorted as Go's slices.Sorted.
    for (key, value) in values {
        let name = if namespace.is_empty() {
            key.clone()
        } else {
            format!("{namespace}.{key}")
        };
        if let toml::Value::Table(table) = value {
            apply_config(parser, &name, table)?;
            continue;
        }
        let index = match parser.find(&name) {
            Some(i) if !COMMAND_ONLY.contains(&name.as_str()) => i,
            _ => return Err(format!("unknown setting {}", strconv::quote(&name))),
        };
        if parser.set_on_command_line(index) {
            continue; // The command line takes precedence.
        }
        let items: Vec<&toml::Value> = match value {
            toml::Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        let (_, spec) = parser.spec(index);
        if let super::options::FieldMut::List(list) = (spec.get_mut)(&mut parser.options) {
            list.clear();
        }
        for item in items {
            let text = sprint(item);
            parser.set(index, Some(&text)).map_err(|e| {
                let text = match e {
                    SetError::Flag(e) => e.message,
                    SetError::Convert(text) => text,
                };
                format!("setting {}: {text}", strconv::quote(&name))
            })?;
        }
        parser.clear_command_line_mark(index);
    }
    Ok(())
}

/// Go's `fmt.Sprint` of a value BurntSushi/toml decodes into `any`.
fn sprint(value: &toml::Value) -> String {
    match value {
        toml::Value::String(s) => s.clone(),
        toml::Value::Integer(n) => n.to_string(),
        toml::Value::Float(f) => strconv::format_float(*f, b'g', -1, 64),
        toml::Value::Boolean(b) => b.to_string(),
        toml::Value::Datetime(d) => d.to_string(),
        toml::Value::Array(items) => {
            let items: Vec<String> = items.iter().map(sprint).collect();
            format!("[{}]", items.join(" "))
        }
        toml::Value::Table(table) => {
            let items: Vec<String> = table
                .iter()
                .map(|(k, v)| format!("{k}:{}", sprint(v)))
                .collect();
            format!("map[{}]", items.join(" "))
        }
    }
}

/// Writes the parser's current settings as a TOML file that [`load_config`]
/// accepts, each preceded by its description.
pub fn print_config(parser: &Parser) -> String {
    let mut buf = String::new();
    for group in GROUPS {
        if !group.namespace.is_empty() {
            buf.push_str(&format!("\n[{}]\n", group.namespace));
        }
        for spec in group.options {
            if COMMAND_ONLY.contains(&long_name(group, spec).as_str()) {
                continue;
            }
            buf.push_str(&format!("\n# {}\n", spec.description));
            let key = toml_key(spec.long);
            match (spec.get)(&parser.options) {
                Field::Str(s) => buf.push_str(&format!("{key} = {}\n", toml_string(s))),
                Field::Bool(b) => buf.push_str(&format!("{key} = {b}\n")),
                Field::Int(n) | Field::Int64(n) => buf.push_str(&format!("{key} = {n}\n")),
                // An empty list has no TOML value of its own; show the key.
                Field::List(l) if l.is_empty() => buf.push_str(&format!("# {} = []\n", spec.long)),
                Field::List(l) => {
                    let items: Vec<String> = l.iter().map(|s| toml_string(s)).collect();
                    buf.push_str(&format!("{key} = [{}]\n", items.join(", ")));
                }
            }
        }
    }
    buf.strip_prefix('\n').unwrap_or(&buf).to_string()
}

/// BurntSushi/toml's key: bare when it can be, quoted otherwise.
fn toml_key(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-');
    if bare {
        key.to_string()
    } else {
        toml_string(key)
    }
}

/// BurntSushi/toml's `writeQuoted` with its `dblQuotedReplacer`.
fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
