//! The CBOR subset WebAuthn needs, decoded as go-webauthn's `webauthncbor`
//! package configures `github.com/fxamacker/cbor/v2`: definite lengths only,
//! no tags, duplicate map keys rejected, at most [`MAX_NESTED_LEVELS`] levels
//! of arrays and maps, at most [`MAX_ITEMS`] elements per array or pairs per
//! map, and text strings that must be valid UTF-8. [`unmarshal`] rejects bytes
//! after the item; [`unmarshal_first`] reports how many bytes it used.
//! [`marshal`] writes CTAP2 canonical CBOR, as `webauthncbor.Marshal` does.
//!
//! Decoding runs in two passes, as fxamacker's does. The first checks that
//! the input is well formed and within the limits; the second reads it the
//! way the Go type it is decoded into would: [`Value`] is Go's `any`,
//! [`decode_string_map`] is `map[string]any`, and [`decode_struct`] is a
//! struct with `cbor` or `json` field tags. Their errors carry fxamacker's
//! messages, since go-webauthn puts some of them in its own.

use std::fmt;

/// The deepest nesting of arrays and maps go-webauthn accepts.
pub const MAX_NESTED_LEVELS: usize = 5;
/// fxamacker's default cap on array elements and on map pairs.
pub const MAX_ITEMS: u64 = 131_072;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Major {
    Unsigned,
    Negative,
    Bytes,
    Text,
    Array,
    Map,
    Tag,
    Simple,
}

impl Major {
    fn of(initial: u8) -> Major {
        match initial >> 5 {
            0 => Major::Unsigned,
            1 => Major::Negative,
            2 => Major::Bytes,
            3 => Major::Text,
            4 => Major::Array,
            5 => Major::Map,
            6 => Major::Tag,
            _ => Major::Simple,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Major::Unsigned => "positive integer",
            Major::Negative => "negative integer",
            Major::Bytes => "byte string",
            Major::Text => "UTF-8 text string",
            Major::Array => "array",
            Major::Map => "map",
            Major::Tag => "tag",
            Major::Simple => "primitives",
        }
    }
}

/// A decoding failure, with fxamacker's error text.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// No item at all (Go's `io.EOF`).
    Eof,
    /// The input ends inside an item (Go's `io.ErrUnexpectedEOF`).
    UnexpectedEof,
    Syntax(String),
    MaxNestedLevel,
    MaxArrayElements,
    MaxMapPairs,
    IndefiniteLength(&'static str),
    Tag,
    ExtraneousData {
        len: usize,
        index: usize,
    },
    InvalidUtf8,
    DuplicateKey {
        key: String,
        index: usize,
    },
    InvalidMapKeyType(&'static str),
    UnmarshalType {
        cbor_type: &'static str,
        go_type: &'static str,
        field: Option<String>,
        message: Option<String>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Eof => f.write_str("EOF"),
            Error::UnexpectedEof => f.write_str("unexpected EOF"),
            Error::Syntax(message) => f.write_str(message),
            Error::MaxNestedLevel => {
                write!(f, "cbor: exceeded max nested level {MAX_NESTED_LEVELS}")
            }
            Error::MaxArrayElements => write!(
                f,
                "cbor: exceeded max number of elements {MAX_ITEMS} for CBOR array"
            ),
            Error::MaxMapPairs => write!(
                f,
                "cbor: exceeded max number of key-value pairs {MAX_ITEMS} for CBOR map"
            ),
            Error::IndefiniteLength(t) => write!(f, "cbor: indefinite-length {t} isn't allowed"),
            Error::Tag => f.write_str("cbor: CBOR tag isn't allowed"),
            Error::ExtraneousData { len, index } => write!(
                f,
                "cbor: {len} bytes of extraneous data starting at index {index}"
            ),
            Error::InvalidUtf8 => f.write_str("cbor: invalid UTF-8 string"),
            Error::DuplicateKey { key, index } => write!(
                f,
                "cbor: found duplicate map key {key} at map element index {index}"
            ),
            Error::InvalidMapKeyType(t) => write!(f, "cbor: invalid map key type: {t}"),
            Error::UnmarshalType {
                cbor_type,
                go_type,
                field,
                message,
            } => {
                match field {
                    Some(field) => write!(
                        f,
                        "cbor: cannot unmarshal {cbor_type} into Go struct field {field} of type {go_type}"
                    )?,
                    None => write!(
                        f,
                        "cbor: cannot unmarshal {cbor_type} into Go value of type {go_type}"
                    )?,
                }
                match message {
                    Some(message) => write!(f, " ({message})"),
                    None => Ok(()),
                }
            }
        }
    }
}

impl std::error::Error for Error {}

/// A decoded item, as Go's `any` holds it. CBOR `undefined` decodes to
/// [`Value::Null`], as both become Go's `nil`.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Unsigned(u64),
    /// The negative integer `-1 - n`.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Pairs in input order.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
    /// An unassigned simple value.
    Simple(u8),
    Float(f64),
}

impl Value {
    /// The value Go's `.(int64)` type assertion finds: only negative
    /// integers decode to `int64`, and only those that fit.
    pub fn as_go_int64(&self) -> Option<i64> {
        match *self {
            Value::Negative(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    /// The value Go's `.(uint64)` type assertion finds.
    pub fn as_go_uint64(&self) -> Option<u64> {
        match *self {
            Value::Unsigned(n) => Some(n),
            _ => None,
        }
    }

    /// Go's map key equality between the decoded values.
    fn key_eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Float(a), Value::Float(b)) => a == b,
            _ => self == other,
        }
    }

    /// The `%#v` rendering Go's duplicate key error uses, for the keys that
    /// can reach it.
    fn go_syntax(&self) -> String {
        match self {
            Value::Unsigned(n) => format!("0x{n:x}"),
            Value::Negative(n) => format!("-{}", u128::from(*n) + 1),
            Value::Text(s) => format!("{s:?}"),
            Value::Bytes(b) => format!("{b:?}"),
            Value::Bool(b) => b.to_string(),
            Value::Null => "<nil>".into(),
            Value::Simple(n) => format!("0x{n:x}"),
            Value::Float(x) => x.to_string(),
            Value::Array(_) | Value::Map(_) => "?".into(),
        }
    }
}

/// A well-formed item and the bytes that encode it.
#[derive(Clone, Debug)]
pub(crate) struct Node<'a> {
    pub raw: &'a [u8],
    pub kind: Kind<'a>,
}

#[derive(Clone, Debug)]
pub(crate) enum Kind<'a> {
    Unsigned(u64),
    Negative(u64),
    Bytes(&'a [u8]),
    Text(&'a [u8]),
    Array(Vec<Node<'a>>),
    Map(Vec<(Node<'a>, Node<'a>)>),
    Bool(bool),
    /// `null` or `undefined`.
    Nil,
    Simple(u8),
    Float(f64),
}

impl Node<'_> {
    fn major(&self) -> Major {
        Major::of(self.raw[0])
    }

    fn type_name(&self) -> &'static str {
        self.major().name()
    }
}

struct Head {
    major: Major,
    info: u8,
    value: u64,
}

fn read_head(data: &[u8], off: &mut usize) -> Result<Head, Error> {
    let Some(&initial) = data.get(*off) else {
        return Err(Error::UnexpectedEof);
    };
    *off += 1;
    let major = Major::of(initial);
    let info = initial & 0x1f;
    let size = match info {
        0..=23 => {
            return Ok(Head {
                major,
                info,
                value: u64::from(info),
            })
        }
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        31 => {
            return match major {
                Major::Unsigned | Major::Negative | Major::Tag => Err(Error::Syntax(format!(
                    "cbor: invalid additional information {info} for type {}",
                    major.name()
                ))),
                Major::Simple => Err(Error::Syntax("cbor: unexpected \"break\" code".into())),
                _ => Err(Error::IndefiniteLength(major.name())),
            }
        }
        _ => {
            return Err(Error::Syntax(format!(
                "cbor: invalid additional information {info} for type {}",
                major.name()
            )))
        }
    };
    let bytes = data.get(*off..*off + size).ok_or(Error::UnexpectedEof)?;
    *off += size;
    let value = bytes.iter().fold(0u64, |acc, &b| acc << 8 | u64::from(b));
    if major == Major::Simple && size == 1 && value < 32 {
        return Err(Error::Syntax(format!(
            "cbor: invalid simple value {value} for type primitives"
        )));
    }
    Ok(Head { major, info, value })
}

/// The first, well-formedness pass: returns the depth reached.
fn wellformed(data: &[u8], off: &mut usize, depth: usize) -> Result<usize, Error> {
    let head = read_head(data, off)?;
    match head.major {
        Major::Bytes | Major::Text => {
            let len = usize::try_from(head.value)
                .ok()
                .filter(|&n| n <= isize::MAX as usize)
                .ok_or_else(|| {
                    Error::Syntax(format!(
                        "cbor: {} length {} is too large, causing integer overflow",
                        head.major.name(),
                        head.value
                    ))
                })?;
            if data.len() - *off < len {
                return Err(Error::UnexpectedEof);
            }
            *off += len;
            Ok(depth)
        }
        Major::Array | Major::Map => {
            let depth = depth + 1;
            if depth > MAX_NESTED_LEVELS {
                return Err(Error::MaxNestedLevel);
            }
            if head.value > isize::MAX as u64 {
                return Err(Error::Syntax(format!(
                    "cbor: {} length {} is too large, it would cause integer overflow",
                    head.major.name(),
                    head.value
                )));
            }
            if head.value > MAX_ITEMS {
                return Err(if head.major == Major::Array {
                    Error::MaxArrayElements
                } else {
                    Error::MaxMapPairs
                });
            }
            let count = if head.major == Major::Map {
                head.value * 2
            } else {
                head.value
            };
            let mut deepest = depth;
            for _ in 0..count {
                deepest = deepest.max(wellformed(data, off, depth)?);
            }
            Ok(deepest)
        }
        Major::Tag => Err(Error::Tag),
        _ => Ok(depth),
    }
}

/// The second pass, over input the first accepted.
fn node<'a>(data: &'a [u8], off: &mut usize) -> Node<'a> {
    let start = *off;
    let head = read_head(data, off).expect("checked by wellformed");
    let kind = match head.major {
        Major::Unsigned => Kind::Unsigned(head.value),
        Major::Negative => Kind::Negative(head.value),
        Major::Bytes | Major::Text => {
            let len = head.value as usize;
            let bytes = &data[*off..*off + len];
            *off += len;
            if head.major == Major::Bytes {
                Kind::Bytes(bytes)
            } else {
                Kind::Text(bytes)
            }
        }
        Major::Array => Kind::Array((0..head.value).map(|_| node(data, off)).collect()),
        Major::Map => Kind::Map(
            (0..head.value)
                .map(|_| {
                    let key = node(data, off);
                    (key, node(data, off))
                })
                .collect(),
        ),
        Major::Tag => unreachable!("tags are rejected by wellformed"),
        Major::Simple => match head.info {
            20 => Kind::Bool(false),
            21 => Kind::Bool(true),
            22 | 23 => Kind::Nil,
            25 => Kind::Float(f64::from(f16_to_f32(head.value as u16))),
            26 => Kind::Float(f64::from(f32::from_bits(head.value as u32))),
            27 => Kind::Float(f64::from_bits(head.value)),
            _ => Kind::Simple(head.value as u8),
        },
    };
    Node {
        raw: &data[start..*off],
        kind,
    }
}

fn f16_to_f32(bits: u16) -> f32 {
    let sign = u32::from(bits >> 15) << 31;
    let exponent = u32::from((bits >> 10) & 0x1f);
    let mantissa = u32::from(bits & 0x3ff);
    let magnitude = match (exponent, mantissa) {
        (0, 0) => 0,
        (0, m) => {
            // Subnormal: normalize the mantissa.
            let shift = m.leading_zeros() - 21;
            ((127 - 15 + 1 - shift) << 23) | ((m << shift) & 0x3ff) << 13
        }
        (0x1f, m) => 0x7f80_0000 | m << 13,
        (e, m) => ((e + 127 - 15) << 23) | m << 13,
    };
    f32::from_bits(sign | magnitude)
}

/// Checks `data` holds exactly one well-formed item and returns it.
pub(crate) fn parse(data: &[u8]) -> Result<Node<'_>, Error> {
    if data.is_empty() {
        return Err(Error::Eof);
    }
    let mut off = 0;
    wellformed(data, &mut off, 0)?;
    if off != data.len() {
        return Err(Error::ExtraneousData {
            len: data.len() - off,
            index: off,
        });
    }
    let mut off = 0;
    Ok(node(data, &mut off))
}

/// Checks `data` starts with a well-formed item and returns it.
pub(crate) fn parse_first(data: &[u8]) -> Result<Node<'_>, Error> {
    if data.is_empty() {
        return Err(Error::Eof);
    }
    let mut off = 0;
    wellformed(data, &mut off, 0)?;
    let mut off = 0;
    Ok(node(data, &mut off))
}

/// Go's `webauthncbor.Unmarshal` into `any`.
pub fn unmarshal(data: &[u8]) -> Result<Value, Error> {
    to_value(&parse(data)?)
}

/// Go's `webauthncbor.UnmarshalFirst` into `any`: the value and the number
/// of bytes it used.
pub fn unmarshal_first(data: &[u8]) -> Result<(Value, usize), Error> {
    let item = parse_first(data)?;
    Ok((to_value(&item)?, item.raw.len()))
}

fn text(bytes: &[u8]) -> Result<String, Error> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| Error::InvalidUtf8)
}

/// Keeps the first error and goes on, as fxamacker does for every error but
/// a duplicate key.
fn first(slot: &mut Option<Error>, err: Error) {
    slot.get_or_insert(err);
}

/// Decodes an item into Go's `any`.
pub(crate) fn to_value(item: &Node<'_>) -> Result<Value, Error> {
    Ok(match &item.kind {
        Kind::Unsigned(n) => Value::Unsigned(*n),
        Kind::Negative(n) => Value::Negative(*n),
        Kind::Bytes(b) => Value::Bytes(b.to_vec()),
        Kind::Text(b) => Value::Text(text(b)?),
        Kind::Bool(b) => Value::Bool(*b),
        Kind::Nil => Value::Null,
        Kind::Simple(n) => Value::Simple(*n),
        Kind::Float(x) => Value::Float(*x),
        Kind::Array(items) => {
            let mut err = None;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                match to_value(item) {
                    Ok(v) => out.push(v),
                    Err(e) => {
                        out.push(Value::Null);
                        first(&mut err, e);
                    }
                }
            }
            match err {
                Some(e) => return Err(e),
                None => Value::Array(out),
            }
        }
        Kind::Map(pairs) => {
            let mut err = None;
            let mut out: Vec<(Value, Value)> = Vec::with_capacity(pairs.len());
            for (i, (key, value)) in pairs.iter().enumerate() {
                let key = match to_value(key) {
                    Ok(key) => key,
                    Err(e) => {
                        first(&mut err, e);
                        continue;
                    }
                };
                match &key {
                    Value::Array(_) => {
                        first(&mut err, Error::InvalidMapKeyType("[]interface {}"));
                        continue;
                    }
                    Value::Map(_) => {
                        first(
                            &mut err,
                            Error::InvalidMapKeyType("map[interface {}]interface {}"),
                        );
                        continue;
                    }
                    // Go decodes these to a big.Int, which is not hashable.
                    Value::Negative(n) if *n > i64::MAX as u64 => {
                        first(&mut err, Error::InvalidMapKeyType("big.Int"));
                        continue;
                    }
                    _ => {}
                }
                let value = match to_value(value) {
                    Ok(value) => value,
                    Err(e) => {
                        first(&mut err, e);
                        continue;
                    }
                };
                if let Some(existing) = out.iter_mut().find(|(k, _)| k.key_eq(&key)) {
                    return Err(Error::DuplicateKey {
                        key: existing.0.go_syntax(),
                        index: i,
                    });
                }
                out.push((key, value));
            }
            match err {
                Some(e) => return Err(e),
                None => Value::Map(out),
            }
        }
    })
}

/// Decodes an item into Go's `map[string]any`. A CBOR null is Go's nil map,
/// returned as `None`.
pub(crate) fn decode_string_map(item: &Node<'_>) -> Result<Option<Vec<(String, Value)>>, Error> {
    let pairs = match &item.kind {
        Kind::Map(pairs) => pairs,
        Kind::Nil => return Ok(None),
        _ => {
            return Err(Error::UnmarshalType {
                cbor_type: item.type_name(),
                go_type: "map[string]interface {}",
                field: None,
                message: None,
            })
        }
    };
    let mut err = None;
    let mut out: Vec<(String, Value)> = Vec::with_capacity(pairs.len());
    for (i, (key, value)) in pairs.iter().enumerate() {
        let key = match &key.kind {
            Kind::Text(b) => match text(b) {
                Ok(key) => key,
                Err(e) => {
                    first(&mut err, e);
                    continue;
                }
            },
            Kind::Nil => String::new(),
            _ => {
                first(
                    &mut err,
                    Error::UnmarshalType {
                        cbor_type: key.type_name(),
                        go_type: "string",
                        field: None,
                        message: None,
                    },
                );
                continue;
            }
        };
        let value = match to_value(value) {
            Ok(value) => value,
            Err(e) => {
                first(&mut err, e);
                continue;
            }
        };
        if out.iter().any(|(k, _)| *k == key) {
            return Err(Error::DuplicateKey {
                key: format!("{key:?}"),
                index: i,
            });
        }
        out.push((key, value));
    }
    match err {
        Some(e) => Err(e),
        None => Ok(Some(out)),
    }
}

/// How a struct field is named in CBOR: a `json`/`cbor` tag name, or a
/// `keyasint` integer.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FieldKey {
    Name(&'static str),
    Int(i64),
}

/// The Go type of a struct field.
#[derive(Clone, Copy, Debug)]
pub(crate) enum FieldKind {
    Int64,
    ByteSlice,
    String,
    /// `cbor.RawMessage`: the item's encoding, kept undecoded.
    Raw,
}

pub(crate) struct Field {
    pub key: FieldKey,
    pub kind: FieldKind,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) enum FieldValue<'a> {
    #[default]
    Absent,
    Int64(i64),
    Bytes(Vec<u8>),
    String(String),
    Raw(&'a [u8]),
}

impl<'a> FieldValue<'a> {
    pub fn int64(&self) -> i64 {
        match self {
            FieldValue::Int64(n) => *n,
            _ => 0,
        }
    }

    pub fn bytes(&self) -> Vec<u8> {
        match self {
            FieldValue::Bytes(b) => b.clone(),
            _ => Vec::new(),
        }
    }

    pub fn string(&self) -> String {
        match self {
            FieldValue::String(s) => s.clone(),
            _ => String::new(),
        }
    }

    pub fn raw(&self) -> &'a [u8] {
        match self {
            FieldValue::Raw(r) => r,
            _ => &[],
        }
    }
}

fn field_name(key: FieldKey) -> String {
    match key {
        FieldKey::Name(name) => name.to_owned(),
        FieldKey::Int(n) => n.to_string(),
    }
}

fn decode_field<'a>(
    item: &Node<'a>,
    field: &Field,
    go_type: &'static str,
) -> Result<FieldValue<'a>, Error> {
    let mismatch = |go_field: &'static str, message: Option<String>| Error::UnmarshalType {
        cbor_type: item.type_name(),
        go_type: go_field,
        field: Some(format!("{go_type}.{}", field_name(field.key))),
        message,
    };
    if let FieldKind::Raw = field.kind {
        return Ok(FieldValue::Raw(item.raw));
    }
    if let Kind::Nil = item.kind {
        return Ok(FieldValue::Absent);
    }
    match (field.kind, &item.kind) {
        (FieldKind::Int64, Kind::Unsigned(n)) => i64::try_from(*n)
            .map(FieldValue::Int64)
            .map_err(|_| mismatch("int64", Some(format!("{n} overflows Go's int64")))),
        (FieldKind::Int64, Kind::Negative(n)) => i64::try_from(*n)
            .map(|n| FieldValue::Int64(-1 - n))
            .map_err(|_| mismatch("int64", Some(format!("-1-{n} overflows Go's int64")))),
        (FieldKind::Int64, _) => Err(mismatch("int64", None)),
        (FieldKind::ByteSlice, Kind::Bytes(b)) => Ok(FieldValue::Bytes(b.to_vec())),
        (FieldKind::ByteSlice, _) => Err(mismatch("[]uint8", None)),
        (FieldKind::String, Kind::Text(b)) => text(b).map(FieldValue::String),
        (FieldKind::String, _) => Err(mismatch("string", None)),
        (FieldKind::Raw, _) => unreachable!("handled above"),
    }
}

/// Decodes an item into a Go struct whose fields are `fields`, as
/// fxamacker's `parseMapToStruct` does: names match exactly or else
/// case-insensitively, integer keys match `keyasint` fields, other keys are
/// errors, and unmatched keys are skipped but still checked for duplicates.
/// A CBOR null leaves every field absent.
pub(crate) fn decode_struct<'a>(
    item: &Node<'a>,
    go_type: &'static str,
    fields: &[Field],
) -> Result<Vec<FieldValue<'a>>, Error> {
    let mut out = vec![FieldValue::Absent; fields.len()];
    let pairs = match &item.kind {
        Kind::Map(pairs) => pairs,
        Kind::Nil => return Ok(out),
        _ => {
            return Err(Error::UnmarshalType {
                cbor_type: item.type_name(),
                go_type,
                field: None,
                message: matches!(item.kind, Kind::Array(_))
                    .then(|| "cannot decode CBOR array to struct without toarray option".into()),
            })
        }
    };
    let mut found = vec![false; fields.len()];
    let mut unmatched: Vec<Value> = Vec::new();
    let mut err = None;
    for (i, (key, value)) in pairs.iter().enumerate() {
        let (index, unmatched_key) = match &key.kind {
            Kind::Text(b) => {
                let name = match text(b) {
                    Ok(name) => name,
                    Err(e) => {
                        first(&mut err, e);
                        continue;
                    }
                };
                let exact = fields
                    .iter()
                    .position(|f| matches!(f.key, FieldKey::Name(n) if n == name));
                let folded = || {
                    fields.iter().position(
                        |f| matches!(f.key, FieldKey::Name(n) if n.eq_ignore_ascii_case(&name)),
                    )
                };
                (exact.or_else(folded), Value::Text(name))
            }
            Kind::Unsigned(n) => match i64::try_from(*n) {
                Ok(n) => (int_field(fields, n), int_key(n)),
                Err(_) => {
                    first(
                        &mut err,
                        Error::UnmarshalType {
                            cbor_type: key.type_name(),
                            go_type: "int64",
                            field: None,
                            message: Some(format!("{n} overflows Go's int64")),
                        },
                    );
                    continue;
                }
            },
            Kind::Negative(n) => match i64::try_from(*n) {
                Ok(n) => (int_field(fields, -1 - n), int_key(-1 - n)),
                Err(_) => {
                    first(
                        &mut err,
                        Error::UnmarshalType {
                            cbor_type: key.type_name(),
                            go_type: "int64",
                            field: None,
                            message: Some(format!("-1-{n} overflows Go's int64")),
                        },
                    );
                    continue;
                }
            },
            _ => {
                first(
                    &mut err,
                    Error::UnmarshalType {
                        cbor_type: key.type_name(),
                        go_type: "string",
                        field: None,
                        message: Some(format!(
                            "map key is of type {} and cannot be used to match struct field name",
                            key.type_name()
                        )),
                    },
                );
                match to_value(key) {
                    Ok(Value::Array(_) | Value::Map(_)) | Err(_) => continue,
                    Ok(Value::Negative(n)) if n > i64::MAX as u64 => continue,
                    Ok(other) => (None, other),
                }
            }
        };
        match index {
            Some(index) if found[index] => {
                return Err(Error::DuplicateKey {
                    key: unmatched_key.go_syntax_struct_key(),
                    index: i,
                })
            }
            Some(index) => {
                found[index] = true;
                match decode_field(value, &fields[index], go_type) {
                    Ok(v) => out[index] = v,
                    Err(e) => first(&mut err, e),
                }
            }
            None => {
                if unmatched.iter().any(|k| k.key_eq(&unmatched_key)) {
                    return Err(Error::DuplicateKey {
                        key: unmatched_key.go_syntax_struct_key(),
                        index: i,
                    });
                }
                unmatched.push(unmatched_key);
            }
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok(out),
    }
}

fn int_field(fields: &[Field], n: i64) -> Option<usize> {
    fields
        .iter()
        .position(|f| matches!(f.key, FieldKey::Int(k) if k == n))
}

/// A struct key read as an integer, which Go holds as an `int64`.
fn int_key(n: i64) -> Value {
    if n < 0 {
        Value::Negative((-1 - n) as u64)
    } else {
        Value::Unsigned(n as u64)
    }
}

impl Value {
    /// Go renders struct keys matched by name as strings and by integer as
    /// `int64`.
    fn go_syntax_struct_key(&self) -> String {
        match self {
            Value::Unsigned(n) => n.to_string(),
            other => other.go_syntax(),
        }
    }
}

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    match n {
        0..=23 => out.push(major | n as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, n as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// Go's `webauthncbor.Marshal` of a decoded value: CTAP2 canonical CBOR,
/// with the shortest integer and length heads, map keys in bytewise order
/// of their encodings, and every float written as a float64, as
/// `cbor.CTAP2EncOptions` does.
pub fn marshal(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode(value, &mut out);
    out
}

fn encode(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Unsigned(n) => head(out, 0, *n),
        Value::Negative(n) => head(out, 1, *n),
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                encode(item, out);
            }
        }
        Value::Map(pairs) => {
            let mut encoded: Vec<(Vec<u8>, &Value)> =
                pairs.iter().map(|(k, v)| (marshal(k), v)).collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            head(out, 5, encoded.len() as u64);
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                encode(value, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Simple(n) if *n < 24 => out.push(0xe0 | n),
        Value::Simple(n) => out.extend_from_slice(&[0xf8, *n]),
        Value::Float(x) => {
            out.push(0xfb);
            out.extend_from_slice(&x.to_bits().to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests;
