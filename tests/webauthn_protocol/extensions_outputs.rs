//! extensions_outputs_test.go, the unmarshal and `Present` cases. The
//! port does not marshal client extension outputs, so
//! TestClientOutputsRoundTrip, TestClientOutputsMarshalJSON*,
//! TestClientOutputsIsZero and TestClientOutputsMap* are not ported.

use apron::webauthn::protocol::AuthenticationExtensionsClientOutputs;
use rust_stdlib::encoding::json;

fn unmarshal(data: &str) -> Result<AuthenticationExtensionsClientOutputs, json::Error> {
    json::unmarshal(data.as_bytes())
}

/// The port keeps only `appid` and which outputs are present; the typed
/// members Go keeps are decoded and dropped.
#[test]
fn test_client_outputs_unmarshal_json() {
    let have = unmarshal(
        r#"{
		"appid": true,
		"credProps": {"rk": false},
		"prf": {"enabled": true, "results": {"first": "YWJj"}},
		"largeBlob": {"supported": true},
		"vendorThing": 7
	}"#,
    )
    .expect("unmarshal");
    assert_eq!(have.appid, Some(true));
    assert_eq!(
        have.present(),
        ["appid", "credProps", "prf", "largeBlob", "vendorThing"]
    );
}

#[test]
fn test_client_outputs_absent_is_not_false() {
    let have = unmarshal("{}").expect("unmarshal");
    assert_eq!(have.appid, None);
    assert!(have.present().is_empty());
}

/// Go builds the outputs as a struct literal; here they come from the
/// JSON a client would send for the same outputs.
#[test]
fn test_client_outputs_present() {
    let have =
        unmarshal(r#"{"appid":false,"credProps":{"rk":true},"vendorThing":1}"#).expect("unmarshal");
    assert_eq!(have.present(), ["appid", "credProps", "vendorThing"]);
}

#[test]
fn test_client_outputs_app_id_wrong_type() {
    let err = unmarshal(r#"{"appid":"not-a-bool"}"#).expect_err("appid string");
    assert_eq!(
        err.to_string(),
        "json: cannot unmarshal string into Go struct field alias.appid of type bool"
    );
}

#[test]
fn test_client_outputs_app_id_wrong_type_case_variant() {
    let err = unmarshal(r#"{"appID":"not-a-bool"}"#).expect_err("appID string");
    assert_eq!(
        err.to_string(),
        "json: cannot unmarshal string into Go struct field alias.appID of type bool"
    );
}

#[test]
fn test_client_outputs_extra_case_insensitive_collision() {
    let have = unmarshal(r#"{"appID":true}"#).expect("unmarshal");
    assert_eq!(have.appid, Some(true));
    assert_eq!(have.present(), ["appid"]);
}
