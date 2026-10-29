//! base64_test.go

use apron::webauthn::protocol::UrlEncodedBase64;
use rust_stdlib::encoding::json::{self, v2};
use rust_stdlib_derive::Deserialize;

// Not ported: ShouldMarshalNil. A nil and an empty Go slice are one
// value in Rust.
#[test]
fn test_url_encoded_base64_marshal_json() {
    let cases = [
        (
            "ShouldMarshalData",
            b"test data".to_vec(),
            "\"dGVzdCBkYXRh\"",
        ),
        ("ShouldMarshalEmpty", Vec::new(), "\"\""),
    ];
    for (name, have, want) in cases {
        let data = v2::marshal(&UrlEncodedBase64(have), &[]).expect(name);
        assert_eq!(String::from_utf8(data).unwrap(), want, "{name}");
    }
}

/// Go calls `UnmarshalJSON` with the raw bytes; the port's entry point is
/// `json::unmarshal`, which first checks the input is JSON at all.
#[test]
fn test_url_encoded_base64_unmarshal_json_error() {
    const NOT_JSON_STRING: &str = "error unmarshalling url encoded base64: expected a JSON string";
    let cases = [
        (
            "ShouldFailInvalidBase64",
            "\"not valid base64!!!\"",
            "illegal base64 data at input byte 3",
        ),
        ("ShouldFailJSONNumber", "123456", NOT_JSON_STRING),
        ("ShouldFailJSONBoolean", "true", NOT_JSON_STRING),
        ("ShouldFailJSONObject", "{\"a\":\"b\"}", NOT_JSON_STRING),
        ("ShouldFailJSONArray", "[\"YWJj\"]", NOT_JSON_STRING),
        (
            // Go's UnmarshalJSON sees the bytes and rejects them as not a
            // string; through json.Unmarshal, as here, the syntax check
            // rejects them first.
            "ShouldFailUnterminatedJSONString",
            "\"YWJj",
            "unexpected end of JSON input",
        ),
    ];
    for (name, data, want) in cases {
        let err = json::unmarshal::<UrlEncodedBase64>(data.as_bytes()).expect_err(name);
        assert_eq!(err.to_string(), want, "{name}");
    }
}

#[derive(Debug, Default, Deserialize)]
struct TestData {
    #[json("string_data")]
    string_data: String,
    #[json("encoded_data")]
    encoded_data: UrlEncodedBase64,
}

#[test]
fn test_base64_unmarshal_json() {
    let cases: [(&str, String, &[u8]); 6] = [
        (
            "ShouldHandleBase64Data",
            format!("\"{}\"", super::URL_SAFE_NO_PAD.encode(b"test base64 data")),
            b"test base64 data",
        ),
        ("ShouldHandleNull", "null".into(), b""),
        (
            "ShouldHandlePaddedBase64Data",
            "\"YWJjZA==\"".into(),
            b"abcd",
        ),
        (
            "ShouldHandleEscapedBase64Data",
            "\"\\u0059\\u0057\\u004a\\u006a\"".into(),
            b"abc",
        ),
        (
            "ShouldHandlePartiallyEscapedBase64Data",
            "\"YW\\u004aj\"".into(),
            b"abc",
        ),
        ("ShouldHandleEmptyString", "\"\"".into(), b""),
    ];
    for (name, message, want) in cases {
        let raw = format!("{{\"string_data\": \"test string\", \"encoded_data\": {message}}}");
        let actual: TestData = json::unmarshal(raw.as_bytes()).expect(name);
        assert_eq!(actual.encoded_data.0, want, "{name}");
        assert_eq!(actual.string_data, "test string", "{name}");
    }
}
