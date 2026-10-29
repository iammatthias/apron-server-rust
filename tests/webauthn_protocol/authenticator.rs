//! authenticator_test.go. Not ported: TestResidentKeyRequired and
//! TestResidentKeyNotRequired (Go's `*bool` helpers; the port's
//! `with_resident_key_requirement` sets the `Option<bool>` itself, which
//! webauthn::test_registration_options covers).

use super::*;
use apron::webauthn::protocol::{AuthenticatorData, AuthenticatorFlags};

const NONE_AUTH_DATA_BASE64: &str = "pkLSG3xtVeHOI8U5mCjSx0m/am7y/gPMnhDN9O1ttItBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQMAxl6G32ykWaLrv/ouCs5HoGsvONqBtOb7ZmyMs8K8PccnwyyqPzWn/yZuyQmQBguvjYSvH6gDBlFG65quUDCSlAQIDJiABIVggyJGP+ra/u/eVjqN4OeYXUShRWxrEeC6Sb5/bZmJ9q8MiWCCHIkRdg5oRb1RHoFVYUpogcjlObCKFsV1ls1T+uUc6rA==";
const ATT_AUTH_DATA_BASE64: &str = "lWkIjx7O4yMpVANdvRDXyuORMFonUbVZu4/Xy7IpvdRBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQIniszxcGnhupdPFOHJIm6dscrWCC2h8xHicBMu91THD0kdOdB0QQtkaEn+6KfsfT1o3NmmFT8YfXrG734WfVSmlAQIDJiABIVggyoHHeiUw5aSbt8/GsL9zaqZGRzV26A4y3CnCGUhVXu4iWCBMnc8za5xgPzIygngAv9W+vZTMGJwwZcM4sjiqkcb/1g==";

const UP: u8 = AuthenticatorFlags::USER_PRESENT;
const BE: u8 = AuthenticatorFlags::BACKUP_ELIGIBLE;
const BS: u8 = AuthenticatorFlags::BACKUP_STATE;

fn flag_cases(name: &str, has: fn(AuthenticatorFlags) -> bool, cases: &[(u8, bool)]) {
    for &(flags, want) in cases {
        assert_eq!(has(AuthenticatorFlags(flags)), want, "{name} {flags:#04x}");
    }
}

#[test]
fn test_authenticator_flags_user_present() {
    flag_cases(
        "UserPresent",
        AuthenticatorFlags::has_user_present,
        &[(0x01, true), (0x10, false)],
    );
}

#[test]
fn test_authenticator_flags_user_verified() {
    flag_cases(
        "UserVerified",
        AuthenticatorFlags::has_user_verified,
        &[(0x04, true), (0x02, false)],
    );
}

#[test]
fn test_authenticator_flags_has_attested_credential_data() {
    flag_cases(
        "HasAttestedCredentialData",
        AuthenticatorFlags::has_attested_credential_data,
        &[(0x40, true), (0x01, false)],
    );
}

#[test]
fn test_authenticator_flags_has_extensions() {
    flag_cases(
        "HasExtensions",
        AuthenticatorFlags::has_extensions,
        &[(0x80, true), (0x01, false)],
    );
}

#[test]
fn test_authenticator_flags_has_backup_eligible() {
    flag_cases(
        "HasBackupEligible",
        AuthenticatorFlags::has_backup_eligible,
        &[(BE, true), (BE | UP, true), (UP, false), (0, false)],
    );
}

#[test]
fn test_authenticator_flags_has_backup_state() {
    flag_cases(
        "HasBackupState",
        AuthenticatorFlags::has_backup_state,
        &[(BS, true), (BS | BE, true), (UP, false), (0, false)],
    );
}

#[test]
fn test_authenticator_data_unmarshal() {
    let none_auth_data = b64std(NONE_AUTH_DATA_BASE64);
    let att_auth_data = b64std(ATT_AUTH_DATA_BASE64);

    // Go asserts only that these decode; the decoded header is checked
    // against the bytes of each vector as well.
    let none = AuthenticatorData::unmarshal(&none_auth_data).expect("NoneMarshallSuccessfully");
    assert_eq!(
        (none.flags, none.counter, none.att_data.credential_id.len()),
        (AuthenticatorFlags(0x41), 0, 64)
    );
    assert_eq!(hexenc::encode(&none.rpid_hash[..8]), "a642d21b7c6d55e1");
    let att = AuthenticatorData::unmarshal(&att_auth_data).expect("AttDataMarshallSuccessfully");
    assert_eq!(
        hexenc::encode(&att.att_data.credential_id[..8]),
        "89e2b33c5c1a786e"
    );

    let bad_auth_data2 = att_auth_data[..54].to_vec();
    let mut bad_auth_data3 = att_auth_data.clone();
    bad_auth_data3[32] &= 0b0011_1111;
    let mut bad_auth_data4 = att_auth_data.clone();
    bad_auth_data4[32] |= 0b1000_0000;
    let mut bad_auth_data5 = att_auth_data.clone();
    bad_auth_data5.extend_from_slice(b"Hello World");

    let cases: [(&str, Vec<u8>, &str, &str); 5] = [
        (
            "AuthenticatorDataTooShort",
            Vec::new(),
            "Authenticator data length too short",
            "Expected data greater than 37 bytes. Got 0 bytes",
        ),
        (
            "AttestedCredentialMissing",
            bad_auth_data2,
            "Attested credential flag set but data is missing",
            "",
        ),
        (
            "AttestedCredentialMissing",
            bad_auth_data3,
            "Attested credential flag not set",
            "",
        ),
        (
            "ExtensionsDataMissing",
            bad_auth_data4,
            "Extensions flag set but extensions data is missing",
            "",
        ),
        (
            "LeftoverBytes",
            bad_auth_data5,
            "Leftover bytes decoding AuthenticatorData",
            "",
        ),
    ];
    for (name, raw, details, info) in cases {
        let err = AuthenticatorData::unmarshal(&raw).expect_err(name);
        assert_eq!(err.to_string(), details, "{name}");
        assert_protocol_error(&err, ErrorType::InvalidRequest, details, info);
    }
}

/// Go calls the private `unmarshalAttestedData`; every vector sets the
/// attested credential data flag and is longer than 55 bytes, so
/// `Unmarshal` reaches it with the same input.
#[test]
fn test_authenticator_data_unmarshal_attested_data() {
    let none_auth_data = b64std(NONE_AUTH_DATA_BASE64);
    let att_auth_data = b64std(ATT_AUTH_DATA_BASE64);
    assert_eq!(
        AuthenticatorData::unmarshal(&none_auth_data)
            .expect("None Marshall Successfully")
            .att_data
            .aaguid,
        vec![0; 16]
    );
    assert_eq!(
        AuthenticatorData::unmarshal(&att_auth_data)
            .expect("Att Data Marshall Successfully")
            .att_data
            .credential_public_key
            .len(),
        77
    );

    let mut bad_auth_data1 = att_auth_data.clone();
    bad_auth_data1[53..55].copy_from_slice(&256u16.to_be_bytes());
    let mut bad_auth_data2 = att_auth_data.clone();
    bad_auth_data2.resize(att_auth_data.len() + 1023 + 1, 0);
    bad_auth_data2[53..55].copy_from_slice(&1024u16.to_be_bytes());
    let mut bad_auth_data3 = att_auth_data[..119].to_vec();
    bad_auth_data3.extend_from_slice(&hex("83FF20030102"));

    let cases = [
        (
            "Data length too short",
            bad_auth_data1,
            "Authenticator attestation data length too short",
        ),
        (
            "ID length too long",
            bad_auth_data2,
            "Authenticator attestation data credential id length too long",
        ),
        (
            "Could not unmarshal Credential Public Key",
            bad_auth_data3,
            "Could not unmarshal Credential Public Key: cbor: unexpected \"break\" code",
        ),
    ];
    for (name, raw, details) in cases {
        let err = AuthenticatorData::unmarshal(&raw).expect_err(name);
        assert_eq!(err.to_string(), details, "{name}");
        assert_protocol_error(&err, ErrorType::InvalidRequest, details, "");
    }
}

#[test]
fn test_authenticator_data_verify() {
    let data = |rpid_hash: &[u8], flags: u8| AuthenticatorData {
        rpid_hash: rpid_hash.to_vec(),
        flags: AuthenticatorFlags(flags),
        ..AuthenticatorData::default()
    };
    struct Case {
        name: &'static str,
        data: AuthenticatorData,
        rp_id_hash: &'static [u8],
        app_id_hash: Option<&'static [u8]>,
        uv: bool,
        up: bool,
        info: Option<&'static str>,
    }
    let cases = [
        Case {
            name: "Success",
            data: data(&[1, 2, 3], 0x05),
            rp_id_hash: &[1, 2, 3],
            app_id_hash: None,
            uv: false,
            up: false,
            info: None,
        },
        Case {
            name: "RP hash mismatch",
            data: data(&[0xff], 0),
            rp_id_hash: &[0xaa],
            app_id_hash: None,
            uv: false,
            up: false,
            info: Some("RP Hash mismatch. Expected aa and Received ff"),
        },
        Case {
            name: "AppID hash matches",
            data: data(&[1, 2, 3], 0x05),
            rp_id_hash: &[0xaa],
            app_id_hash: Some(&[1, 2, 3]),
            uv: false,
            up: false,
            info: None,
        },
        Case {
            name: "AppID hash set and only RP ID hash matches",
            data: data(&[1, 2, 3], 0x05),
            rp_id_hash: &[1, 2, 3],
            app_id_hash: Some(&[0xaa]),
            uv: false,
            up: false,
            info: Some("RP Hash mismatch. Expected aa and Received 010203"),
        },
        Case {
            name: "Zero RP ID hash without an AppID",
            data: data(&[0; 32], 0x05),
            rp_id_hash: &[1, 2, 3],
            app_id_hash: None,
            uv: false,
            up: false,
            info: Some("RP Hash mismatch. Expected 010203 and Received 0000000000000000000000000000000000000000000000000000000000000000"),
        },
        Case {
            name: "UP flag not set",
            data: data(&[1, 2, 3], 0x04),
            rp_id_hash: &[1, 2, 3],
            app_id_hash: None,
            uv: false,
            up: true,
            info: Some("User presence required but flag not set by authenticator"),
        },
        Case {
            name: "User verification required",
            data: data(&[1, 2, 3], 0x01),
            rp_id_hash: &[1, 2, 3],
            app_id_hash: None,
            uv: true,
            up: true,
            info: Some("User verification required but flag not set by authenticator"),
        },
    ];
    for tc in cases {
        let result = tc.data.verify(tc.rp_id_hash, tc.app_id_hash, tc.uv, tc.up);
        match tc.info {
            None => assert_eq!(result, Ok(()), "{}", tc.name),
            Some(info) => {
                let err = result.expect_err(tc.name);
                assert_eq!(
                    err.to_string(),
                    "Error validating the authenticator response",
                    "{}",
                    tc.name
                );
                assert_protocol_error(
                    &err,
                    ErrorType::VerificationError,
                    "Error validating the authenticator response",
                    info,
                );
            }
        }
    }
}

#[test]
fn test_authenticator_data_unmarshal_decodes_extensions() {
    let ext_data = cbor::marshal(&Value::Map(vec![(
        Value::Text("minPinLength".into()),
        Value::Unsigned(4),
    )]));
    assert_eq!(hexenc::encode(&ext_data), "a16c6d696e50696e4c656e67746804");
    let mut raw = vec![0u8; 37];
    raw[32] = AuthenticatorFlags::HAS_EXTENSIONS;
    raw.extend_from_slice(&ext_data);

    let auth_data = AuthenticatorData::unmarshal(&raw).expect("unmarshal");
    assert_eq!(
        auth_data.ext_data, ext_data,
        "the raw signed bytes must be preserved"
    );
    assert_eq!(auth_data.ext.expect("ext").min_pin_length, Some(4));
}
