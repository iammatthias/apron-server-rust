//! The request envelope (PROTOCOL.md §1) and the dynamic JSON value the
//! rest of the server builds frames from.

use std::collections::BTreeMap;

use rust_stdlib::encoding::json::jsontext::{self, Value};
use rust_stdlib::encoding::json::v2::{
    self as json, Any, MarshalTo, TypeInfo, TypeKind, UnmarshalFrom,
};
use rust_stdlib_derive::{MarshalTo, UnmarshalFrom};

use super::dispatch::notification_only;

pub const CODE_PARSE_ERROR: i64 = -32700;
pub const CODE_INVALID_REQUEST: i64 = -32600;
pub const CODE_UNSUPPORTED: i64 = -32601;
pub const CODE_INVALID_PARAMS: i64 = -32602;
pub const CODE_INTERNAL_ERROR: i64 = -32603;
pub const CODE_DENIED: i64 = -32001;
pub const CODE_RETRY_AFTER: i64 = -32002;
pub const CODE_TOO_LARGE: i64 = -32003;

/// A JSON value as the server holds it: Go's `any` as `encoding/json` fills
/// it, plus `Ext`, an ext object (§4.12) whose values stay the JSON they
/// arrived as, so a merge or a store keeps them byte for byte, numbers
/// beyond 2^53 included.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum Json {
    #[default]
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Json>),
    Object(Object),
    Ext(ExtObject),
    /// JSON already rendered, such as a logged record placed in a frame.
    Raw(Value),
}

pub type Object = BTreeMap<String, Json>;

/// An ext object (§4.12) keyed by extension name.
pub type ExtObject = BTreeMap<String, Value>;

impl From<Any> for Json {
    fn from(a: Any) -> Json {
        match a {
            Any::Null => Json::Null,
            Any::Bool(b) => Json::Bool(b),
            Any::String(s) => Json::String(s),
            Any::Number(n) => Json::Number(n),
            Any::Array(a) => Json::Array(a.into_iter().map(Json::from).collect()),
            Any::Object(o) => {
                Json::Object(o.into_iter().map(|(k, v)| (k, Json::from(v))).collect())
            }
        }
    }
}

impl From<&str> for Json {
    fn from(s: &str) -> Json {
        Json::String(s.to_owned())
    }
}

impl From<String> for Json {
    fn from(s: String) -> Json {
        Json::String(s)
    }
}

impl From<bool> for Json {
    fn from(b: bool) -> Json {
        Json::Bool(b)
    }
}

impl From<i64> for Json {
    fn from(n: i64) -> Json {
        Json::Number(n as f64)
    }
}

impl From<usize> for Json {
    fn from(n: usize) -> Json {
        Json::Number(n as f64)
    }
}

impl From<Vec<Json>> for Json {
    fn from(a: Vec<Json>) -> Json {
        Json::Array(a)
    }
}

impl From<Object> for Json {
    fn from(o: Object) -> Json {
        Json::Object(o)
    }
}

impl From<ExtObject> for Json {
    fn from(e: ExtObject) -> Json {
        Json::Ext(e)
    }
}

impl From<Value> for Json {
    fn from(v: Value) -> Json {
        Json::Raw(v)
    }
}

impl From<Vec<String>> for Json {
    fn from(a: Vec<String>) -> Json {
        Json::Array(a.into_iter().map(Json::String).collect())
    }
}

impl Json {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Json::Object(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Json::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Go's `asList`: the value as a list, or none.
    pub fn as_list(&self) -> &[Json] {
        match self {
            Json::Array(a) => a,
            _ => &[],
        }
    }

    pub fn is_true(&self) -> bool {
        matches!(self, Json::Bool(true))
    }
}

/// Builds an [`Object`] from `key => value` pairs.
#[macro_export]
macro_rules! obj {
    ($($key:expr => $value:expr),* $(,)?) => {{
        #[allow(unused_mut)]
        let mut o = $crate::server::protocol::Object::new();
        $(o.insert(($key).to_string(), $crate::server::protocol::Json::from($value));)*
        o
    }};
}

fn json_type() -> TypeInfo {
    TypeInfo::of::<Json>("interface {}", TypeKind::Interface)
}

impl MarshalTo for Json {
    fn type_info() -> TypeInfo {
        json_type()
    }

    fn marshal_default(&self, enc: &mut jsontext::Encoder<'_>) -> Result<(), jsontext::Error> {
        match self {
            Json::Null => enc.write_token(&jsontext::null()),
            Json::Bool(b) => json::marshal_value(enc, b),
            Json::Number(n) => json::marshal_value(enc, n),
            Json::String(s) => json::marshal_value(enc, s),
            Json::Array(a) => json::marshal_value(enc, a),
            Json::Object(o) => json::marshal_value(enc, o),
            Json::Raw(raw) => enc.write_value(raw),
            Json::Ext(e) => {
                enc.write_token(&jsontext::begin_object())?;
                for (key, value) in e {
                    enc.write_token(&jsontext::string(key))?;
                    enc.write_value(value)?;
                }
                enc.write_token(&jsontext::end_object())
            }
        }
    }

    fn is_zero_value(&self) -> bool {
        matches!(self, Json::Null)
    }

    fn is_empty_value(&self) -> Option<bool> {
        Some(matches!(self, Json::Null))
    }

    fn marshal_to(&self, enc: &mut jsontext::Encoder<'_>) -> Result<(), jsontext::Error> {
        self.marshal_default(enc)
    }
}

impl UnmarshalFrom for Json {
    fn type_info() -> TypeInfo {
        json_type()
    }

    fn zero() -> Json {
        Json::Null
    }

    fn set_zero(&mut self) {
        *self = Json::Null;
    }

    fn unmarshal_default(
        &mut self,
        dec: &mut jsontext::Decoder<'_>,
    ) -> Result<(), jsontext::Error> {
        let mut any = Any::Null;
        any.unmarshal_default(dec)?;
        *self = Json::from(any);
        Ok(())
    }

    fn unmarshal_from(&mut self, dec: &mut jsontext::Decoder<'_>) -> Result<(), jsontext::Error> {
        self.unmarshal_default(dec)
    }
}

#[derive(Clone, Debug, PartialEq, Default, MarshalTo, UnmarshalFrom)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    #[json("data,omitzero")]
    pub data: Option<Json>,
    /// Set on an error that is shown to the client but is not a policy
    /// violation, such as a mistyped command.
    #[json(skip)]
    pub forgiven: bool,
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> RpcError {
        RpcError {
            code,
            message: message.into(),
            data: None,
            forgiven: false,
        }
    }

    /// Marks the error as not counting toward `Limits.policy_violations`.
    pub fn forgiven(mut self) -> RpcError {
        self.forgiven = true;
        self
    }

    pub fn with_data(code: i64, message: impl Into<String>, data: Object) -> RpcError {
        RpcError {
            code,
            message: message.into(),
            data: Some(Json::Object(data)),
            forgiven: false,
        }
    }
}

#[derive(Clone, Debug, Default, MarshalTo)]
pub struct RpcResponse {
    #[json("id,omitzero")]
    pub id: Option<String>,
    #[json("result,omitzero")]
    pub result: Option<Json>,
    #[json("error,omitzero")]
    pub error: Option<RpcError>,
}

pub type Params = BTreeMap<String, Value>;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Request {
    pub method: String,
    pub params: Params,
    pub id: String,
    pub has_id: bool,
}

fn is_null(raw: &[u8]) -> bool {
    raw.trim_ascii() == b"null"
}

/// Decodes `raw` as a `T`, where a JSON null is refused rather than taken as
/// the zero value.
pub(crate) fn decode_non_null<T: UnmarshalFrom>(raw: &[u8]) -> Option<T> {
    if is_null(raw) {
        return None;
    }
    let mut value = T::zero();
    json::unmarshal(raw, &mut value, &[]).ok()?;
    Some(value)
}

/// Bounds on a frame (Config.frame), apron-server-cloudflare's by default:
/// its size, read before it is parsed; the nesting and count of its JSON
/// values and the size of its request id, checked before it is decoded;
/// and the size of a message's `body.text`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameLimits {
    pub max_bytes: usize,
    pub max_text_bytes: usize,
    pub max_depth: usize,
    pub max_nodes: usize,
    pub max_id_bytes: usize,
}

impl Default for FrameLimits {
    fn default() -> FrameLimits {
        FrameLimits {
            max_bytes: 16 << 10,
            max_text_bytes: 4 << 10,
            max_depth: 8,
            max_nodes: 2048,
            max_id_bytes: 128,
        }
    }
}

/// Counts the values of `payload`, valid JSON, and the deepest nesting of
/// its objects and arrays, the top-level one at depth 1. Object keys are
/// not values.
fn json_shape(payload: &[u8]) -> (usize, usize) {
    let mut decoder = jsontext::Decoder::from_buffer(payload.to_vec(), &[]);
    let (mut nodes, mut depth) = (0, 0);
    while let Ok(token) = decoder.read_token() {
        let kind = token.kind();
        if kind == jsontext::KIND_END_OBJECT || kind == jsontext::KIND_END_ARRAY {
            continue;
        }
        let level = decoder.stack_depth();
        if kind == jsontext::KIND_BEGIN_OBJECT || kind == jsontext::KIND_BEGIN_ARRAY {
            depth = depth.max(level);
        } else if kind == jsontext::KIND_STRING {
            // A name leaves its object an odd number of tokens long.
            let (parent, length) = decoder.stack_index(level);
            if parent == jsontext::KIND_BEGIN_OBJECT && length % 2 == 1 {
                continue;
            }
        }
        nodes += 1;
    }
    (nodes, depth)
}

pub fn parse_request(payload: &[u8], limits: &FrameLimits) -> (Request, Option<RpcError>) {
    let mut req = Request::default();
    if !Value::from(payload).is_valid(&[]) {
        return (req, Some(RpcError::new(CODE_PARSE_ERROR, "Parse error")));
    }
    let Some(object) = decode_non_null::<Params>(payload) else {
        return (
            req,
            Some(RpcError::new(CODE_INVALID_REQUEST, "Invalid request")),
        );
    };

    // method comes first: a server may ignore the id of a notification
    // method and handle the frame as a notification (§1.1), and this one
    // does, whatever the id is.
    let method_ok = match object
        .get("method")
        .and_then(|raw| decode_non_null::<String>(&raw.0))
    {
        Some(method) if !method.is_empty() => {
            req.method = method;
            true
        }
        _ => false,
    };
    if let Some(raw_id) = object.get("id") {
        if !notification_only(&req.method) {
            req.has_id = true;
            match decode_non_null::<String>(&raw_id.0) {
                Some(id) if id.len() <= limits.max_id_bytes => req.id = id,
                _ => {
                    req.has_id = false;
                    return (
                        req,
                        Some(RpcError::new(
                            CODE_INVALID_REQUEST,
                            "Request id must be a bounded string",
                        )),
                    );
                }
            }
        }
    }
    if !method_ok {
        return (
            req,
            Some(RpcError::new(CODE_INVALID_REQUEST, "Invalid request")),
        );
    }
    let (nodes, depth) = json_shape(payload);
    if nodes > limits.max_nodes {
        return (
            req,
            Some(RpcError::new(CODE_TOO_LARGE, "JSON structure is too large")),
        );
    }
    if depth > limits.max_depth {
        return (
            req,
            Some(RpcError::new(CODE_TOO_LARGE, "JSON nesting is too deep")),
        );
    }
    if let Some(raw_params) = object.get("params") {
        match decode_non_null::<Params>(&raw_params.0) {
            Some(params) => req.params = params,
            None => return (req, Some(invalid_params("Params must be an object"))),
        }
    }
    (req, None)
}

fn canonical_params(params: &Params) -> String {
    let raw = encode_json(params).unwrap_or_default();
    let mut value = Json::Null;
    if json::unmarshal(&raw, &mut value, &[]).is_err() {
        return String::from_utf8_lossy(&raw).into_owned();
    }
    match encode_json(&value) {
        Some(canonical) => String::from_utf8_lossy(&canonical).into_owned(),
        None => String::from_utf8_lossy(&raw).into_owned(),
    }
}

pub fn request_fingerprint(req: &Request) -> String {
    format!("{}\x00{}", req.method, canonical_params(&req.params))
}

pub fn response(id: &str, result: Json) -> RpcResponse {
    RpcResponse {
        id: Some(id.to_owned()),
        result: Some(result),
        error: None,
    }
}

/// Builds an error reply. No id omits "id", as for errors not tied to a
/// request (PROTOCOL.md §1.1).
pub fn error_response(id: Option<&str>, e: RpcError) -> RpcResponse {
    RpcResponse {
        id: id.map(str::to_owned),
        result: None,
        error: Some(e),
    }
}

pub fn invalid_params(message: impl Into<String>) -> RpcError {
    RpcError::new(CODE_INVALID_PARAMS, message)
}

pub fn parse_string(params: &Params, name: &str, required: bool) -> Result<String, RpcError> {
    let Some(raw) = params.get(name) else {
        if required {
            return Err(invalid_params(format!("Missing {name}")));
        }
        return Ok(String::new());
    };
    decode_non_null::<String>(&raw.0)
        .ok_or_else(|| invalid_params(format!("{name} must be a string")))
}

/// Reports whether `id` can be a room_id or user_id (§2.4): one that is not
/// empty and has no whitespace or control characters.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && !id.chars().any(|r| r.is_whitespace() || r.is_control())
}

pub fn parse_bool(params: &Params, name: &str, required: bool) -> Result<bool, RpcError> {
    let Some(raw) = params.get(name) else {
        if required {
            return Err(invalid_params(format!("Missing {name}")));
        }
        return Ok(false);
    };
    decode_non_null::<bool>(&raw.0)
        .ok_or_else(|| invalid_params(format!("{name} must be a boolean")))
}

pub fn parse_object(
    params: &Params,
    name: &str,
    required: bool,
) -> Result<Option<Object>, RpcError> {
    let Some(raw) = params.get(name) else {
        if required {
            return Err(invalid_params(format!("Missing {name}")));
        }
        return Ok(None);
    };
    match decode_non_null::<Json>(&raw.0) {
        Some(Json::Object(value)) => Ok(Some(value)),
        _ => Err(invalid_params(format!("{name} must be an object"))),
    }
}

/// Reads an optional ext object of a write (§4.12). The second result
/// reports whether the request carried it.
pub fn parse_ext(params: &Params, name: &str) -> Result<(ExtObject, bool), RpcError> {
    let Some(raw) = params.get(name) else {
        return Ok((ExtObject::new(), false));
    };
    let Some(mut ext) = decode_non_null::<ExtObject>(&raw.0) else {
        return Err(invalid_params(format!("{name} must be an object")));
    };
    for (key, value) in ext.iter_mut() {
        if value.compact(&[]).is_err() {
            return Err(invalid_params(format!("{name}.{key} is not valid JSON")));
        }
    }
    Ok((ext, true))
}

/// Reports whether a compact JSON value is an empty value ("", [], or {}),
/// which clears what it is merged into (§3.3).
pub fn empty_json(value: &Value) -> bool {
    matches!(value.0.as_slice(), b"\"\"" | b"[]" | b"{}")
}

/// Merges a write's ext into the kept one, one level deep (§4.12): each key
/// the write carries replaces the kept value, a key whose value is empty is
/// removed, and keys the write leaves out stay. null is an ordinary value,
/// and an empty write changes nothing. The result is a new object, empty
/// when no key is left; `kept` is not modified.
pub fn merge_ext(kept: &ExtObject, write: &ExtObject) -> ExtObject {
    let mut merged = kept.clone();
    for (key, value) in write {
        if empty_json(value) {
            merged.remove(key);
        } else {
            merged.insert(key.clone(), value.clone());
        }
    }
    merged
}

/// Lists, as their empty values, the keys of a write's ext that cleared a
/// key that was kept, for a notification that carries the change (§4.12).
pub fn cleared_ext(kept: &ExtObject, write: &ExtObject) -> ExtObject {
    write
        .iter()
        .filter(|(key, value)| kept.contains_key(*key) && empty_json(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// The ext of an object decoded with `decode_object`, or an empty one.
pub fn ext_of(value: Option<&Json>) -> ExtObject {
    match value {
        Some(Json::Ext(ext)) => ext.clone(),
        _ => ExtObject::new(),
    }
}

/// Decodes a JSON object, keeping the values of a top-level ext as raw JSON
/// so that re-encoding the object keeps them exactly.
pub fn decode_object(raw: &[u8]) -> Option<Object> {
    let fields = decode_non_null::<BTreeMap<String, Value>>(raw)?;
    let mut value = Object::new();
    for (key, field) in fields {
        if key == "ext" {
            if let Some(ext) = decode_non_null::<ExtObject>(&field.0) {
                value.insert(key, Json::Ext(ext));
                continue;
            }
        }
        if let Some(decoded) = decode_non_null::<Json>(&field.0) {
            value.insert(key, decoded);
        } else if is_null(&field.0) {
            value.insert(key, Json::Null);
        }
    }
    Some(value)
}

/// `jsonOptions`: deterministic, with sorted object keys. Every encoding
/// the server sends or stores goes through these, and so do the tests that
/// compare those bytes with Go's. A function, as `Options` cannot be a
/// constant.
pub fn json_options() -> [json::Options; 1] {
    [json::deterministic(true)]
}

/// Encodes a value with `json_options`, or `None` if it cannot.
pub fn encode_json<T: MarshalTo>(value: &T) -> Option<Vec<u8>> {
    json::marshal(value, &json_options()).ok()
}

/// The size of a value encoded as JSON.
pub fn encoded_size<T: MarshalTo>(value: &T) -> usize {
    encode_json(value).map_or(0, |v| v.len())
}

/// Renders a frame once, for sending to many connections.
pub fn notification(method: &str, params: Object) -> Vec<u8> {
    encode_json(&obj! {"method" => method, "params" => params}).unwrap_or_default()
}

/// Renders a frame around params that are already JSON, as `notification`
/// would with the decoded params ("method" sorts first).
pub fn raw_notification(method: &str, params: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(method.len() + params.len() + 24);
    payload.extend_from_slice(b"{\"method\":");
    rust_stdlib::strconv::append_quote(&mut payload, method);
    payload.extend_from_slice(b",\"params\":");
    payload.extend_from_slice(params);
    payload.push(b'}');
    payload
}

/// Renders a result reply around a result that is already JSON, as
/// `response` would with the decoded result.
pub fn raw_response(id: &str, result: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(id.len() + result.len() + 24);
    payload.extend_from_slice(b"{\"id\":");
    rust_stdlib::strconv::append_quote(&mut payload, id);
    payload.extend_from_slice(b",\"result\":");
    payload.extend_from_slice(result);
    payload.push(b'}');
    payload
}

pub fn format_id(id: i64) -> String {
    id.to_string()
}

/// Go's `%q` of a string.
pub fn quote(s: &str) -> String {
    rust_stdlib::strconv::quote(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malformed_frames() {
        for (input, code, id) in [
            (b"{".as_slice(), CODE_PARSE_ERROR, ""),
            (b"[]", CODE_INVALID_REQUEST, ""),
            (b"null", CODE_INVALID_REQUEST, ""),
            (
                br#"{"method":"message","id":"x","params":[]}"#,
                CODE_INVALID_PARAMS,
                "x",
            ),
            (br#"{"method":"message","id":1}"#, CODE_INVALID_REQUEST, ""),
            // Frames are parsed as RFC 7493 I-JSON: a repeated key or invalid
            // UTF-8 is a parse error rather than silently resolved.
            (
                br#"{"method":"message","id":"x","method":"history"}"#,
                CODE_PARSE_ERROR,
                "",
            ),
            (
                b"{\"method\":\"message\",\"params\":{\"body\":{\"text\":\"\xff\"}}}",
                CODE_PARSE_ERROR,
                "",
            ),
        ] {
            let (req, err) = parse_request(input, &FrameLimits::default());
            let err = err.unwrap_or_else(|| panic!("{}: no error", String::from_utf8_lossy(input)));
            assert_eq!(
                (err.code, req.id.as_str()),
                (code, id),
                "{}",
                String::from_utf8_lossy(input)
            );
        }
    }

    /// Unknown envelope keys are ignored (PROTOCOL.md §1), jsonrpc
    /// included, so a JSON-RPC 2.0 client's frames parse whatever version
    /// they name.
    #[test]
    fn test_unknown_envelope_keys_are_ignored() {
        for input in [
            br#"{"jsonrpc":"2.0","method":"history","id":"x"}"#.as_slice(),
            br#"{"jsonrpc":"1.0","method":"history","id":"x"}"#,
            br#"{"jsonrpc":2,"method":"history","id":"x","extra":{}}"#,
        ] {
            let (req, err) = parse_request(input, &FrameLimits::default());
            assert!(
                err.is_none() && req.method == "history" && req.id == "x",
                "{}: {req:?}, {err:?}",
                String::from_utf8_lossy(input)
            );
        }
    }

    #[test]
    fn ext_round_trips_raw_values_and_sorts_keys() {
        let (ext, present) = parse_ext(
            &decode_non_null::<Params>(
                br#"{"ext":{"zeta":1e400,"__proto__":{"x":1},"n":12345678901234567890}}"#,
            )
            .unwrap(),
            "ext",
        )
        .unwrap();
        assert!(present);
        let encoded = encode_json(&Json::Ext(ext)).unwrap();
        assert_eq!(
            String::from_utf8(encoded).unwrap(),
            r#"{"__proto__":{"x":1},"n":12345678901234567890,"zeta":1e400}"#
        );
        let merged = merge_ext(
            &decode_non_null::<ExtObject>(br#"{"a":1,"b":2}"#).unwrap(),
            &decode_non_null::<ExtObject>(br#"{"a":"","c":null}"#).unwrap(),
        );
        assert_eq!(
            encode_json(&Json::Ext(merged)).unwrap(),
            br#"{"b":2,"c":null}"#
        );
    }

    #[test]
    fn responses_omit_absent_fields_and_keep_empty_results() {
        assert_eq!(
            encode_json(&response("x", Json::Object(Object::new()))).unwrap(),
            br#"{"id":"x","result":{}}"#
        );
        assert_eq!(
            encode_json(&error_response(None, RpcError::new(CODE_DENIED, "no"))).unwrap(),
            br#"{"error":{"code":-32001,"message":"no"}}"#
        );
        let numbers = obj! {"apron" => 9i64, "ping" => 30i64, "ratio" => Json::Number(0.5)};
        assert_eq!(
            encode_json(&numbers).unwrap(),
            br#"{"apron":9,"ping":30,"ratio":0.5}"#
        );
    }
}
