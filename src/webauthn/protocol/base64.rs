use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::encoding::json::{self, jsontext, v2, DecodeState, Node};

/// Go's `URLEncodedBase64`: bytes that travel as unpadded base64url. Reading
/// accepts and drops trailing `=`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UrlEncodedBase64(pub Vec<u8>);

impl UrlEncodedBase64 {
    /// Go's `String`.
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0)
    }
}

impl From<Vec<u8>> for UrlEncodedBase64 {
    fn from(bytes: Vec<u8>) -> UrlEncodedBase64 {
        UrlEncodedBase64(bytes)
    }
}

/// Go's `UnmarshalJSON`.
fn decode(node: &Node<'_>, cx: &mut DecodeState) -> Result<Vec<u8>, json::Error> {
    if node.is_null() {
        return Ok(Vec::new());
    }
    if node.raw().first() != Some(&b'"') {
        return Err(json::Error::custom(
            "error unmarshalling url encoded base64: expected a JSON string",
        ));
    }
    let text = <String as json::Deserialize>::unmarshal_json(node, cx)?;
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .map_err(json::Error::custom)
}

impl json::Deserialize for UrlEncodedBase64 {
    fn from_json(value: &json::Value) -> Result<UrlEncodedBase64, json::Error> {
        match value {
            json::Value::Null => Ok(UrlEncodedBase64::default()),
            json::Value::String(text) => URL_SAFE_NO_PAD
                .decode(text.trim_end_matches('='))
                .map(UrlEncodedBase64)
                .map_err(json::Error::custom),
            _ => Err(json::Error::custom(
                "error unmarshalling url encoded base64: expected a JSON string",
            )),
        }
    }

    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, json::Error> {
        decode(node, cx).map(UrlEncodedBase64)
    }
    fn json_zero() -> Result<Self, json::Error> {
        Ok(Self::default())
    }
}

impl v2::MarshalTo for UrlEncodedBase64 {
    fn type_info() -> v2::TypeInfo {
        v2::TypeInfo::of::<UrlEncodedBase64>("protocol.URLEncodedBase64", v2::TypeKind::Slice)
    }

    fn marshal_default(&self, enc: &mut jsontext::Encoder<'_>) -> Result<(), jsontext::Error> {
        self.encode().marshal_default(enc)
    }

    fn is_zero_value(&self) -> bool {
        self.0.is_empty()
    }

    fn is_empty_value(&self) -> Option<bool> {
        Some(self.0.is_empty())
    }
}
