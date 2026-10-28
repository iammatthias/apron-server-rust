//! go-webauthn v0.18.2's own tests, for the subset src/webauthn ports. Each
//! module holds the cases of one Go test file, under the Go test names, with
//! the Go vectors and expected errors. Large vectors live in
//! tests/data/webauthn/, copied verbatim from the Go test files.
//!
//! A Go case that exercises something the port leaves out (attestation
//! formats other than `none` and packed self attestation, the metadata
//! service, AppID, opaque origins, `http.Request` parsing, msgp, ES256K,
//! ML-DSA) is not ported. A case whose vector uses an attestation format the
//! port rejects asserts the rejection instead.

use apron::cbor::{self, Value};
use apron::webauthn::protocol::{Error, ErrorType};
use rust_stdlib::encoding::base64::{STANDARD, URL_SAFE_NO_PAD};
use rust_stdlib::encoding::hex as hexenc;

macro_rules! vector {
    ($name:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/webauthn/",
            $name
        ))
    };
}

fn hex(s: &str) -> Vec<u8> {
    hexenc::decode(s).expect("hex vector")
}

fn b64url(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64url vector")
}

fn b64std(s: &str) -> Vec<u8> {
    STANDARD.decode(s).expect("base64 vector")
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|s| s.to_string()).collect()
}

/// Go's `AssertIsProtocolError`.
#[track_caller]
fn assert_protocol_error(err: &Error, kind: ErrorType, details: &str, info: &str) {
    assert_eq!(
        (err.kind, err.details.as_str(), err.info.as_str()),
        (kind, details, info)
    );
}

/// The COSE key of an attestation object, as Go's
/// `MustExtractCBORKeyFromAttestationObject` finds it.
fn cose_key_from_attestation_object(attestation_object: &[u8]) -> Vec<u8> {
    let Value::Map(members) = cbor::unmarshal(attestation_object).expect("attestation object")
    else {
        panic!("attestation object is not a map");
    };
    let auth_data = members
        .into_iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(k), Value::Bytes(v)) if k == "authData" => Some(v),
            _ => None,
        })
        .expect("authData");
    let id_len = usize::from(u16::from_be_bytes([auth_data[53], auth_data[54]]));
    auth_data[55 + id_len..].to_vec()
}

mod client {
    //! client_test.go. Not ported: TestFullyQualifiedOrigin
    //! (`FullyQualifiedOrigin` is not in the port) and
    //! TestIsOpaqueOriginInHaystack (opaque origins).

    use super::*;
    use apron::webauthn::protocol::{
        create_challenge, is_origin_in_haystack, CeremonyType, CollectedClientData, TokenBinding,
        TopOriginVerificationMode,
    };

    fn setup_collected_client_data(
        challenge: &str,
        origin: &str,
        top_origin: &str,
        cross_origin: bool,
    ) -> CollectedClientData {
        CollectedClientData {
            kind: CeremonyType::CREATE,
            challenge: challenge.into(),
            origin: origin.into(),
            top_origin: top_origin.into(),
            cross_origin,
            ..CollectedClientData::default()
        }
    }

    enum Want {
        Ok,
        Text(&'static str),
        Protocol(ErrorType, &'static str, &'static str),
    }

    struct Case {
        name: &'static str,
        origin: &'static str,
        top_origin: &'static str,
        cross_origin: bool,
        rp_origins: Option<&'static [&'static str]>,
        rp_top_origins: Option<&'static [&'static str]>,
        mode: TopOriginVerificationMode,
        allow_cross_origin: bool,
        ceremony: Option<CeremonyType>,
        want: Want,
    }

    const BASE: Case = Case {
        name: "",
        origin: "http://example.com",
        top_origin: "",
        cross_origin: false,
        rp_origins: None,
        rp_top_origins: None,
        mode: TopOriginVerificationMode::Explicit,
        allow_cross_origin: false,
        ceremony: None,
        want: Want::Ok,
    };

    // Not ported: ShouldSucceedOpaqueOrigin, ShouldFailOpaqueOriginNotConfigured,
    // ShouldFailOpaqueOriginDifferingInCase,
    // ShouldFailOpaqueOriginResemblingAURLDifferingInCase,
    // ShouldFailOpaqueTopOriginImplicit, ShouldFailOpaqueTopOriginAuto and
    // ShouldFailOpaqueTopOriginExplicit, which configure RPOpaqueOrigins.
    #[test]
    fn test_verify_collected_client_data() {
        let cases = [
            Case {
                name: "ShouldSucceed",
                top_origin: "http://example.com",
                cross_origin: true,
                allow_cross_origin: true,
                ..BASE
            },
            Case {
                name: "ShouldSucceedNoTopOrigin",
                cross_origin: true,
                allow_cross_origin: true,
                ..BASE
            },
            Case {
                name: "ShouldSucceedTopOriginDifferentFromOrigin",
                top_origin: "http://example2.com",
                cross_origin: true,
                allow_cross_origin: true,
                ..BASE
            },
            Case {
                name: "ShouldFailTopOriginMismatch",
                top_origin: "http://example2.com",
                cross_origin: true,
                allow_cross_origin: true,
                rp_top_origins: Some(&["https://example3.com"]),
                want: Want::Text("Error validating top origin"),
                ..BASE
            },
            Case {
                name: "ShouldSucceedTopOriginImplicit",
                top_origin: "http://example.com",
                cross_origin: true,
                allow_cross_origin: true,
                mode: TopOriginVerificationMode::Implicit,
                ..BASE
            },
            Case {
                name: "ShouldSucceedTopOriginAuto",
                top_origin: "http://example.com",
                cross_origin: true,
                allow_cross_origin: true,
                rp_top_origins: Some(&["https://example.com"]),
                mode: TopOriginVerificationMode::Auto,
                ..BASE
            },
            Case {
                name: "ShouldSucceedMultipleExpectedOrigins",
                top_origin: "http://example.com",
                cross_origin: true,
                allow_cross_origin: true,
                rp_origins: Some(&[
                    "https://exmaple.com",
                    "9C:B4:AE:EF:05:53:6E:73:0E:C4:B8:02:E7:67:F6:7D:A4:E7:BC:26:D7:42:B5:27:FF:01:7D:68:2A:EB:FA:1D",
                    "http://example.com",
                ]),
                ..BASE
            },
            Case {
                // Go passes the mode -1, which no constant names; the port's
                // unset mode is the one its verifier does not implement.
                name: "ShouldFailTopOriginInvalidMode",
                top_origin: "http://example.com",
                cross_origin: true,
                allow_cross_origin: true,
                rp_top_origins: Some(&["https://example.com"]),
                mode: TopOriginVerificationMode::Default,
                want: Want::Protocol(
                    ErrorType::NotImplemented,
                    "Error handling unknown Top Origin verification mode",
                    "",
                ),
                ..BASE
            },
            Case {
                name: "ShouldFailCrossOriginNotAllowed",
                top_origin: "http://example.com",
                cross_origin: true,
                want: Want::Protocol(
                    ErrorType::VerificationError,
                    "Error validating cross origin flag",
                    "The cross origin flag is invalid due to the configuration.",
                ),
                ..BASE
            },
            Case {
                name: "ShouldFailUnexpectedOrigin",
                top_origin: "http://example.com",
                cross_origin: true,
                allow_cross_origin: true,
                rp_origins: Some(&["http://different.com"]),
                want: Want::Protocol(
                    ErrorType::VerificationError,
                    "Error validating origin",
                    "Expected Values: [http://different.com], Received: http://example.com",
                ),
                ..BASE
            },
            Case {
                name: "ShouldFailTopOriginWithoutCrossOrigin",
                top_origin: "http://example2.com",
                want: Want::Protocol(
                    ErrorType::VerificationError,
                    "Error validating topOrigin",
                    "The topOrigin can't have values unless crossOrigin is true.",
                ),
                ..BASE
            },
            Case {
                name: "ShouldFailUnexpectedTopOrigin",
                top_origin: "http://example.com",
                cross_origin: true,
                allow_cross_origin: true,
                rp_origins: Some(&["http://example.com"]),
                rp_top_origins: Some(&["http://different.com"]),
                want: Want::Text("Error validating top origin"),
                ..BASE
            },
            Case {
                name: "ShouldFailCeremonyMismatch",
                ceremony: Some(CeremonyType::ASSERT),
                want: Want::Protocol(
                    ErrorType::VerificationError,
                    "Error validating ceremony type",
                    "Expected Value: webauthn.get, Received: webauthn.create",
                ),
                ..BASE
            },
        ];
        for tc in cases {
            let challenge = create_challenge().encode();
            let ccd =
                setup_collected_client_data(&challenge, tc.origin, tc.top_origin, tc.cross_origin);
            let rp_origins = tc
                .rp_origins
                .map_or_else(|| vec![ccd.origin.clone()], strings);
            let rp_top_origins = tc
                .rp_top_origins
                .map_or_else(|| vec![ccd.top_origin.clone()], strings);
            let ceremony = tc.ceremony.clone().unwrap_or_else(|| ccd.kind.clone());
            let result = ccd.verify(
                &challenge,
                &ceremony,
                &rp_origins,
                &rp_top_origins,
                tc.mode,
                tc.allow_cross_origin,
            );
            match tc.want {
                Want::Ok => assert_eq!(result, Ok(()), "{}", tc.name),
                Want::Text(text) => {
                    assert_eq!(result.unwrap_err().to_string(), text, "{}", tc.name)
                }
                Want::Protocol(kind, details, info) => {
                    let err = result.unwrap_err();
                    assert_eq!(
                        (err.kind, err.details.as_str(), err.info.as_str()),
                        (kind, details, info),
                        "{}",
                        tc.name
                    );
                }
            }
        }
    }

    #[test]
    fn test_verify_collected_client_data_incorrect_challenge() {
        let challenge = create_challenge().encode();
        let ccd = setup_collected_client_data(
            &challenge,
            "http://example.com",
            "http://example.com",
            true,
        );
        let bogus = create_challenge().encode();
        let err = ccd
            .verify(
                &bogus,
                &ccd.kind,
                std::slice::from_ref(&ccd.origin),
                std::slice::from_ref(&ccd.top_origin),
                TopOriginVerificationMode::Explicit,
                true,
            )
            .unwrap_err();
        assert_protocol_error(
            &err,
            ErrorType::VerificationError,
            "Error validating challenge",
            &format!("Expected b Value: \"{bogus}\"\nReceived b: \"{challenge}\"\n"),
        );
    }

    #[test]
    fn test_verify_collected_client_data_token_binding() {
        let binding = |status: &str, id: &str| {
            Some(TokenBinding {
                status: status.into(),
                id: id.into(),
            })
        };
        let cases = [
            ("ShouldSucceedWithNilTokenBinding", None, None),
            (
                "ShouldSucceedWithPresentStatus",
                binding("present", "abc"),
                None,
            ),
            (
                "ShouldSucceedWithSupportedStatus",
                binding("supported", ""),
                None,
            ),
            (
                "ShouldSucceedWithNotSupportedStatus",
                binding("not-supported", ""),
                None,
            ),
            (
                "ShouldFailWithEmptyStatus",
                binding("", ""),
                Some("Error decoding clientData, token binding present without status"),
            ),
            (
                "ShouldFailWithInvalidStatus",
                binding("invalid-status", ""),
                Some("Error decoding clientData, token binding present with invalid status"),
            ),
        ];
        for (name, token_binding, want) in cases {
            let challenge = create_challenge().encode();
            let mut ccd = setup_collected_client_data(&challenge, "http://example.com", "", false);
            ccd.token_binding = token_binding;
            let result = ccd.verify(
                &challenge,
                &CeremonyType::CREATE,
                &[ccd.origin.clone()],
                &[],
                TopOriginVerificationMode::Explicit,
                false,
            );
            assert_eq!(
                result.map_err(|err| err.to_string()),
                want.map_or(Ok(()), |text| Err(text.to_string())),
                "{name}"
            );
        }
    }

    #[test]
    fn test_is_origin_in_haystack() {
        let cases: &[(&str, &str, &[&str], bool)] = &[
            (
                "ShouldHandleFullyQualifiedOrigin",
                "https://app.example.com",
                &["https://app.example.com"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginCaseInsensitiveScheme",
                "https://app.example.com",
                &["HTTPS://app.example.com"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginCaseInsensitiveHost",
                "https://app.EXAMPLE.com",
                &["https://app.example.com"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginWithPort",
                "https://app.example.com:443",
                &["https://app.example.com:443"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDifferentScheme",
                "http://app.example.com",
                &["https://app.example.com"],
                false,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDifferentPort",
                "https://app.example.com:443",
                &["https://app.example.com"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDifferentPortNotMatchingScheme",
                "https://app.example.com:80",
                &["https://app.example.com"],
                false,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDifferentPath",
                "https://app.example.com/abc",
                &["https://app.example.com"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDifferentQuery",
                "https://app.example.com/?abc=123",
                &["https://app.example.com"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDifferentQueryCount",
                "https://app.example.com/?abc=123",
                &["https://app.example.com/?zyz=123&abc=123"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDifferentQueryOrder",
                "https://app.example.com/?abc=123&xyz=123",
                &["https://app.example.com/?xyz=123&abc=123"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDifferentQueryValue",
                "https://app.example.com/?abc=123&xyz=123",
                &["https://app.example.com/?xyz=1234&abc=123"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginFragment",
                "https://app.example.com/#abc",
                &["https://app.example.com/#abc"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginFragmentDifferent",
                "https://app.example.com/#abc",
                &["https://app.example.com/#abc2"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginWithoutAllowed",
                "https://app.example.com",
                &[],
                false,
            ),
            (
                "ShouldHandleFullyQualifiedOriginWithTrailingSlashes",
                "https://app.example.com/",
                &["https://app.example.com"],
                true,
            ),
            (
                "ShouldHandleNativeAppAndroid",
                "android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69f0",
                &["android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69f0"],
                true,
            ),
            (
                "ShouldHandleNativeAppAndroidCaseSensitive",
                "android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69F0",
                &["android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69f0"],
                false,
            ),
            (
                "ShouldHandleNonFQDNOrigin",
                "https://user:password@app.example.com/",
                &["https://app.example.com/"],
                true,
            ),
            (
                "ShouldHandleNonFQDNOriginExactStringMatch",
                "https://user:password@app.example.com/",
                &["https://user:password@app.example.com/"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDefaultPortEquivalentHTTPS",
                "https://app.example.com:443",
                &["https://app.example.com"],
                true,
            ),
            (
                "ShouldHandleFullyQualifiedOriginDefaultPortEquivalentHTTP",
                "http://app.example.com:80",
                &["http://app.example.com"],
                true,
            ),
            (
                "ShouldHandleInvalidURLAsSimpleStringMatch",
                "http://app.example.%%%&123?1",
                &["http://app.example.%%%&123?1"],
                true,
            ),
        ];
        for (name, origin, haystack, want) in cases {
            assert_eq!(
                is_origin_in_haystack(origin, &strings(haystack)),
                *want,
                "{name}"
            );
        }
    }
}

mod authenticator {
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
        let att =
            AuthenticatorData::unmarshal(&att_auth_data).expect("AttDataMarshallSuccessfully");
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
}

mod base64 {
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
        const NOT_JSON_STRING: &str =
            "error unmarshalling url encoded base64: expected a JSON string";
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
}

mod extensions_outputs {
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
        let have = unmarshal(r#"{"appid":false,"credProps":{"rk":true},"vendorThing":1}"#)
            .expect("unmarshal");
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
}

use apron::webauthn::protocol::webauthncose::CoseAlgorithmIdentifier;
use apron::webauthn::protocol::{
    parse_credential_creation_response_bytes, parse_credential_request_response_bytes,
    CredentialParameter, CredentialType, ParsedCredentialAssertionData,
    ParsedCredentialCreationData, TopOriginVerificationMode,
};
use rust_stdlib_crypto::sha256;

fn params(algorithms: &[i64]) -> Vec<CredentialParameter> {
    algorithms
        .iter()
        .map(|&alg| CredentialParameter {
            kind: CredentialType::PUBLIC_KEY,
            algorithm: CoseAlgorithmIdentifier(alg),
        })
        .collect()
}

/// Go's `attestationTestUnpackResponse`.
fn unpack_creation(response: &str) -> ParsedCredentialCreationData {
    parse_credential_creation_response_bytes(response.as_bytes()).expect("parse registration")
}

fn client_data_hash(parsed: &ParsedCredentialCreationData) -> [u8; 32] {
    sha256::sum256(&parsed.raw.attestation_response.client_data_json.0)
}

/// A registration response body, as Go's test fixtures marshal one.
fn creation_body(id: &[u8], client_data_json: &[u8], attestation_object: &[u8]) -> String {
    let id = URL_SAFE_NO_PAD.encode(id);
    format!(
        r#"{{"id":"{id}","rawId":"{id}","type":"public-key","response":{{"attestationObject":"{}","clientDataJSON":"{}"}}}}"#,
        URL_SAFE_NO_PAD.encode(attestation_object),
        URL_SAFE_NO_PAD.encode(client_data_json)
    )
}

/// The members of a COSE key in a fixed order, for comparing keys as Go
/// compares the `map[any]any` it decodes them to.
fn cose_members(key: &[u8]) -> Vec<(String, Value)> {
    let Value::Map(members) = cbor::unmarshal(key).expect("COSE key") else {
        panic!("COSE key is not a map");
    };
    let mut members: Vec<(String, Value)> = members
        .into_iter()
        .map(|(k, v)| (format!("{k:?}"), v))
        .collect();
    members.sort_by(|a, b| a.0.cmp(&b.0));
    members
}

mod attestation {
    //! attestation_test.go. Not ported:
    //! TestAttestationObject_VerifyAttestation_HandlerErrors, which registers
    //! custom formats in Go's attestation registry.

    use super::*;
    use apron::webauthn::protocol::AttestationObject;

    const RESPONSES: [&str; 4] = [
        vector!("attestation_response_0.json"),
        vector!("attestation_response_1.json"),
        vector!("attestation_response_2.json"),
        vector!("attestation_response_3.json"),
    ];

    /// Go reads the challenge, RP ID, origin (the RP name) and parameters
    /// from `testAttestationOptions`; they are inlined here.
    #[test]
    fn test_attestation_verify() {
        struct Case {
            name: &'static str,
            response: &'static str,
            challenge: &'static str,
            rp_id: &'static str,
            origin: &'static str,
            algorithms: &'static [i64],
            want: Result<&'static str, (ErrorType, &'static str, &'static str)>,
        }
        let cases = [
            Case {
                name: "ShouldVerifySelfAttestationEC256MacOS",
                response: RESPONSES[0],
                challenge: "rWiex8xDOPfiCgyFu4BLW6vVOmXKgPwHrlMCgEs9SBA",
                rp_id: "localhost",
                origin: "http://localhost:9005",
                algorithms: &[-7],
                want: Ok("basic_surrogate"),
            },
            Case {
                // Go verifies this fido-u2f attestation; the port rejects
                // the format as unsupported.
                name: "ShouldVerifyDirectAttestationEC256Titan",
                response: RESPONSES[1],
                challenge: "-Ri5NZTzJ8b6mvW3TVScLotEoALfgBa2Bn4YSaIObHc",
                rp_id: "webauthn.io",
                origin: "https://webauthn.io",
                algorithms: &[-7],
                want: Err((
                    ErrorType::InvalidAttestation,
                    "Invalid attestation format",
                    "Attestation format fido-u2f is unsupported",
                )),
            },
            Case {
                name: "ShouldVerifyNoneAttestationEC256Titan",
                response: RESPONSES[2],
                challenge: "sVt4ScceMzqFSnfAq8hgLzblvo3fa4_aFVEcIESHIJ0",
                rp_id: "webauthn.io",
                origin: "https://webauthn.io",
                algorithms: &[-7],
                want: Ok("none"),
            },
            Case {
                // Go verifies this packed attestation's x5c chain; the port
                // rejects packed with x5c as unsupported.
                name: "ShouldVerifyPackedAttestationGramThanos",
                response: RESPONSES[3],
                challenge: "Dw4NDAsKCQgHBgUEAwIBAA",
                rp_id: "gramthanos.github.io",
                origin: "https://gramthanos.github.io",
                algorithms: &[-7, -37, -257, -8],
                want: Err((
                    ErrorType::InvalidAttestation,
                    "Basic attestation with an x5c certificate chain is not supported",
                    "",
                )),
            },
        ];
        for tc in cases {
            let mut pcc = unpack_creation(tc.response);
            let result = pcc.verify(
                tc.challenge,
                tc.rp_id,
                &[tc.origin.to_string()],
                &[],
                TopOriginVerificationMode::Explicit,
                false,
                false,
                false,
                &params(tc.algorithms),
            );
            match tc.want {
                Ok(kind) => {
                    assert_eq!(result.map(|hash| hash.len()), Ok(32), "{}", tc.name);
                    assert_eq!(pcc.response.attestation_object.kind, kind, "{}", tc.name);
                }
                Err((kind, details, info)) => {
                    let err = result.expect_err(tc.name);
                    assert_protocol_error(&err, kind, details, info);
                }
            }
        }
    }

    #[test]
    fn test_packed_attestation_verification() {
        let pcc = unpack_creation(RESPONSES[0]);
        let mut att = pcc.response.attestation_object.clone();
        assert_eq!(att.verify_attestation(&client_data_hash(&pcc)), Ok(()));
        assert_eq!(att.kind, "basic_surrogate");
    }

    /// Go calls `AuthenticatorAttestationResponse.Parse`, which reports
    /// "Error parsing the authenticator response"; the port reaches it
    /// through `ParseCredentialCreationResponseBytes`, which wraps that error
    /// as Go's does.
    #[test]
    fn test_attestation_response_parse_errors() {
        let cases: [(&str, &[u8], &[u8]); 2] = [
            ("ShouldFailInvalidClientDataJSON", b"not-json", &[0xa0]),
            (
                "ShouldFailInvalidAttestationObjectCBOR",
                br#"{"type":"webauthn.create","challenge":"dGVzdA","origin":"https://example.com"}"#,
                b"not-cbor",
            ),
        ];
        for (name, client_data_json, attestation_object) in cases {
            let body = creation_body(b"test", client_data_json, attestation_object);
            let err = parse_credential_creation_response_bytes(body.as_bytes()).expect_err(name);
            assert_protocol_error(
                &err,
                ErrorType::ParseError,
                "Error parsing attestation response",
                "",
            );
        }
    }

    #[test]
    fn test_attestation_response_parse_rejects_trailing_cbor() {
        let pcc = unpack_creation(RESPONSES[0]);
        let raw = &pcc.raw.attestation_response;
        let body = creation_body(
            &pcc.raw_id,
            &raw.client_data_json.0,
            &raw.attestation_object.0,
        );
        let reparsed =
            parse_credential_creation_response_bytes(body.as_bytes()).expect("untouched object");
        assert_eq!(reparsed.response.attestation_object.format, "packed");

        let mut attestation_object = raw.attestation_object.0.clone();
        attestation_object.push(0x01);
        let body = creation_body(&pcc.raw_id, &raw.client_data_json.0, &attestation_object);
        let err = parse_credential_creation_response_bytes(body.as_bytes()).expect_err("trailing");
        assert_protocol_error(
            &err,
            ErrorType::ParseError,
            "Error parsing attestation response",
            "",
        );
    }

    #[test]
    fn test_attestation_object_verify_attestation_errors() {
        let cases = [
            (
                "ShouldFailNoneFormatWithStatement",
                AttestationObject {
                    format: "none".into(),
                    att_statement: Some(vec![("key".into(), Value::Text("value".into()))]),
                    ..AttestationObject::default()
                },
            ),
            (
                "ShouldFailUnsupportedFormat",
                AttestationObject {
                    format: "unsupported-format".into(),
                    att_statement: Some(Vec::new()),
                    ..AttestationObject::default()
                },
            ),
        ];
        for (name, mut att) in cases {
            let err = att.verify_attestation(b"hash").expect_err(name);
            assert_eq!(err.to_string(), "Invalid attestation format", "{name}");
        }
    }

    #[test]
    fn test_attestation_object_verify_algorithm_mismatch() {
        let pcc = unpack_creation(RESPONSES[0]);
        let mut att = pcc.response.attestation_object.clone();
        let err = att
            .verify(
                "localhost",
                &client_data_hash(&pcc),
                false,
                false,
                &params(&[-257]),
            )
            .expect_err("RS256 only");
        assert_eq!(err.to_string(), "Invalid attestation format");
    }
}

mod attestation_packed {
    //! attestation_packed_test.go. Not ported, as the port rejects packed
    //! attestation with an x5c chain: TestPackedFormat_BasicAttestationErrors,
    //! TestPackedFormat_BasicAttestationSignatureAndTimeErrors and
    //! TestPackedFormat_BasicAttestationCertRequirements.

    use super::*;
    use apron::webauthn::protocol::AttestationObject;

    const ES256: &str = vector!("packed_es256.json");
    const ES512: &str = vector!("packed_es512.json");
    const SOLO2: &str = vector!("packed_solo2.json");
    const SELF_ES256: &str = vector!("attestation_response_0.json");

    /// Go calls the private `attestationFormatValidationHandlerPacked`; the
    /// port's entry point is `VerifyAttestation`, which dispatches to it.
    #[test]
    fn test_verify_packed_format() {
        let x5c_unsupported = Err((
            ErrorType::InvalidAttestation,
            "Basic attestation with an x5c certificate chain is not supported",
        ));
        let cases = [
            // Go verifies the x5c chain of this and the Solo2 vector as
            // basic_full; the port rejects packed with x5c.
            ("ShouldSuccessfullyVerifyES256", ES256, x5c_unsupported),
            (
                "ShouldSuccessfullyVerifyES512SelfAttestation",
                ES512,
                Ok("basic_surrogate"),
            ),
            ("ShouldSuccessfullyVerifySolo2", SOLO2, x5c_unsupported),
        ];
        for (name, response, want) in cases {
            let pcc = unpack_creation(response);
            let mut att = pcc.response.attestation_object.clone();
            let result = att.verify_attestation(&client_data_hash(&pcc));
            match want {
                Ok(kind) => {
                    assert_eq!(result, Ok(()), "{name}");
                    assert_eq!(att.kind, kind, "{name}");
                }
                Err((kind, details)) => {
                    let err = result.expect_err(name);
                    assert_eq!((err.kind, err.details.as_str()), (kind, details), "{name}");
                }
            }
        }
    }

    fn packed(statement: Vec<(&str, Value)>) -> AttestationObject {
        AttestationObject {
            format: "packed".into(),
            att_statement: Some(
                statement
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            ),
            ..AttestationObject::default()
        }
    }

    const ES256_ALG: Value = Value::Negative(6);

    #[test]
    fn test_packed_format_handler_errors() {
        let cases = [
            ("ShouldFailMissingAlg", vec![], "Error retrieving alg value"),
            (
                "ShouldFailAlgWrongType",
                vec![("alg", Value::Text("not-int".into()))],
                "Error retrieving alg value",
            ),
            (
                "ShouldFailMissingSig",
                vec![("alg", ES256_ALG)],
                "Error retrieving sig value",
            ),
            (
                "ShouldFailSigWrongType",
                vec![("alg", ES256_ALG), ("sig", Value::Text("not-bytes".into()))],
                "Error retrieving sig value",
            ),
            (
                "ShouldReturnECDAANotImplemented",
                vec![
                    ("alg", ES256_ALG),
                    ("sig", Value::Bytes(b"sig".to_vec())),
                    ("ecdaaKeyId", Value::Bytes(b"keyid".to_vec())),
                ],
                "This field is not yet supported by the WebAuthn spec",
            ),
        ];
        for (name, statement, want) in cases {
            let err = packed(statement)
                .verify_attestation(b"hash")
                .expect_err(name);
            assert_eq!(err.to_string(), want, "{name}");
        }
    }

    /// Go calls the private `handleSelfAttestation(alg, pub, "auth", "hash",
    /// "sig")`; here the same inputs reach it through `VerifyAttestation`.
    #[test]
    fn test_packed_format_self_attestation_errors() {
        let valid_pub_key = unpack_creation(ES512)
            .response
            .attestation_object
            .auth_data
            .att_data
            .credential_public_key;
        let cases = [
            (
                "ShouldFailInvalidPublicKey",
                b"not-cbor".to_vec(),
                "Error parsing the public key: Unsupported Public Key Type",
            ),
            (
                "ShouldFailAlgorithmMismatch",
                valid_pub_key,
                "Public key algorithm does not equal att statement algorithm",
            ),
        ];
        for (name, public_key, want) in cases {
            let mut att = packed(vec![
                ("alg", ES256_ALG),
                ("sig", Value::Bytes(b"sig".to_vec())),
            ]);
            att.raw_auth_data = b"auth".to_vec();
            att.auth_data.att_data.credential_public_key = public_key;
            let err = att.verify_attestation(b"hash").expect_err(name);
            assert_eq!(err.to_string(), want, "{name}");
        }
    }

    /// Go calls the private `verifyKeyAlgorithm(keyAlg, attAlg)`; here an
    /// ES256 self attestation carries the statement algorithm.
    #[test]
    fn test_verify_key_algorithm() {
        let pcc = unpack_creation(SELF_ES256);
        let hash = client_data_hash(&pcc);
        let cases = [
            ("ShouldSucceedWhenMatch", Value::Negative(6), None),
            (
                "ShouldFailWhenMismatch",
                Value::Negative(256),
                Some("Public key algorithm does not equal att statement algorithm"),
            ),
        ];
        for (name, alg, want) in cases {
            let mut att = pcc.response.attestation_object.clone();
            for (key, value) in att.att_statement.as_mut().expect("statement") {
                if key == "alg" {
                    *value = alg.clone();
                }
            }
            let result = att.verify_attestation(&hash).map_err(|err| err.to_string());
            assert_eq!(
                result,
                want.map_or(Ok(()), |w| Err(w.to_string())),
                "{name}"
            );
        }
    }
}

mod credential {
    //! credential_test.go. Not ported: the `Response` and `ResponseBody`
    //! subtests of TestParseCredentialCreationResponse and
    //! TestParseCredentialCreationResponse_NilRequest (`http.Request` and
    //! `io.Reader` parsing), and TestGetAppID (AppID).

    use super::*;
    use apron::webauthn::protocol::{
        AuthenticatorAttachment, AuthenticatorFlags, AuthenticatorTransport, CeremonyType,
        CollectedClientData,
    };

    const SUCCESS: &str = vector!("credential_creation_success.json");
    const TRAILING_DATA: &str = vector!("credential_creation_trailingData.json");

    const ID: &str =
        "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g";
    const AUTH_DATA: &str = "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw";
    const RPID_HASH: &str = "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA";
    const CREDENTIAL_PUB_KEY: &str = "pSJYIMfCKfxl2SvnqJIiHQysHmpmITNgtCkQ5ESExSRjqrhXAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNc";
    const ATT_OBJECT: &str = "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw";
    const CLIENT_DATA_JSON: &str = "eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ";

    /// Go compares whole structs, including `Raw` and the client extension
    /// outputs, which the port cannot build by hand; each field is compared
    /// instead, and the outputs through `appid` and `Present`.
    #[test]
    fn test_parse_credential_creation_response() {
        let actual = parse_credential_creation_response_bytes(SUCCESS.as_bytes())
            .expect("ShouldParseCredentialRequest");
        assert_eq!(actual.id, ID);
        assert_eq!(actual.kind, "public-key");
        assert_eq!(actual.raw_id, b64url(ID));
        assert_eq!(actual.client_extension_results.appid, Some(true));
        assert_eq!(actual.client_extension_results.present(), ["appid"]);
        assert_eq!(
            actual.authenticator_attachment,
            AuthenticatorAttachment::PLATFORM
        );

        assert_eq!(actual.raw.id, ID);
        assert_eq!(actual.raw.kind, "public-key");
        assert_eq!(actual.raw.raw_id.0, b64url(ID));
        assert_eq!(
            actual.raw.client_extension_results,
            actual.client_extension_results
        );
        assert_eq!(actual.raw.authenticator_attachment, "platform");
        let raw = &actual.raw.attestation_response;
        assert_eq!(raw.client_data_json.0, b64url(CLIENT_DATA_JSON));
        assert_eq!(raw.attestation_object.0, b64url(ATT_OBJECT));
        assert_eq!(raw.transports, ["usb", "nfc", "fake"]);

        assert_eq!(
            actual.response.transports,
            [
                AuthenticatorTransport::USB,
                AuthenticatorTransport::NFC,
                AuthenticatorTransport::new("fake")
            ]
        );
        assert_eq!(
            actual.response.collected_client_data,
            CollectedClientData {
                kind: CeremonyType::new("webauthn.create"),
                challenge: "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE".into(),
                origin: "https://webauthn.io".into(),
                ..CollectedClientData::default()
            }
        );
        let att = &actual.response.attestation_object;
        assert_eq!(att.format, "none");
        assert_eq!(att.raw_auth_data, b64url(AUTH_DATA));
        assert_eq!(att.auth_data.rpid_hash, b64url(RPID_HASH));
        assert_eq!(att.auth_data.counter, 0);
        assert_eq!(att.auth_data.flags, AuthenticatorFlags(0x41));
        assert_eq!(att.auth_data.att_data.aaguid, vec![0; 16]);
        assert_eq!(att.auth_data.att_data.credential_id, b64url(ID));
        assert_eq!(
            cose_members(&att.auth_data.att_data.credential_public_key),
            cose_members(&b64url(CREDENTIAL_PUB_KEY))
        );

        let err = parse_credential_creation_response_bytes(TRAILING_DATA.as_bytes())
            .expect_err("ShouldHandleTrailingData");
        assert_eq!(err.to_string(), "Parse error for Registration");
        assert_protocol_error(
            &err,
            ErrorType::InvalidRequest,
            "Parse error for Registration",
            "body contains trailing data",
        );
    }

    /// Go builds the parsed data by hand from the same vector this test
    /// parses. On the error case Go also returns the client data hash; the
    /// port returns only the error.
    #[test]
    fn test_parsed_credential_creation_data_verify() {
        let expected_hash = vec![
            0xa, 0xaf, 0x43, 0xda, 0x7e, 0xd3, 0x94, 0x98, 0x9b, 0xbc, 0x47, 0xcb, 0x0, 0x72, 0x6b,
            0xbc, 0xf3, 0xa2, 0x4a, 0x49, 0x5f, 0x84, 0x4f, 0x45, 0x97, 0x91, 0x6a, 0x2d, 0xff,
            0x47, 0xbc, 0xad,
        ];
        let verify = |pcc: &mut ParsedCredentialCreationData| {
            pcc.verify(
                "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE",
                "webauthn.io",
                &strings(&["https://webauthn.io"]),
                &[],
                TopOriginVerificationMode::Explicit,
                false,
                false,
                false,
                &params(&[-7]),
            )
        };

        let mut pcc = unpack_creation(SUCCESS);
        assert_eq!(
            verify(&mut pcc),
            Ok(expected_hash),
            "SuccessfulVerificationTest"
        );

        let mut pcc = unpack_creation(SUCCESS);
        pcc.id = "bm90LXRoZS1hdHRlc3RlZC1jcmVkZW50aWFsLWlkISE".into();
        pcc.raw_id = b"not-the-attested-credential-id!!".to_vec();
        let err = verify(&mut pcc).expect_err("ShouldFailWhenRawIDIsNotTheAttestedCredentialID");
        assert_eq!(
            err.to_string(),
            "Error validating the attested credential id"
        );
    }

    /// Go calls `CredentialCreationResponse.Parse` on a struct; the port
    /// parses the JSON of that struct.
    #[test]
    fn test_credential_creation_response_parse_errors() {
        let cases = [
            ("ShouldFailMissingID", r#"{}"#, "Missing ID"),
            (
                "ShouldFailIDNotBase64",
                r#"{"id":"not valid base64 %%%"}"#,
                "ID not base64.RawURLEncoded",
            ),
            (
                "ShouldFailMissingType",
                r#"{"id":"dGVzdA"}"#,
                "Missing type",
            ),
            (
                "ShouldFailBadType",
                r#"{"id":"dGVzdA","type":"bad-type"}"#,
                "Type not public-key",
            ),
            (
                "ShouldFailRawIDMismatch",
                r#"{"id":"dGVzdA","type":"public-key","rawId":"bm90IHRlc3Q"}"#,
                "ID does not match rawId",
            ),
            (
                "ShouldFailRawIDMissing",
                r#"{"id":"dGVzdA","type":"public-key"}"#,
                "ID does not match rawId",
            ),
        ];
        for (name, body, info) in cases {
            let err = parse_credential_creation_response_bytes(body.as_bytes()).expect_err(name);
            assert_eq!(err.to_string(), "Parse error for Registration", "{name}");
            assert_protocol_error(
                &err,
                ErrorType::InvalidRequest,
                "Parse error for Registration",
                info,
            );
        }
    }

    #[test]
    fn test_credential_creation_response_parse_raw_id_mismatch_is_distinguishable() {
        let err = parse_credential_creation_response_bytes(
            br#"{"id":"dGVzdA","type":"public-key","rawId":"bm90IHRlc3Q"}"#,
        )
        .expect_err("mismatch");
        assert_eq!(err.details, "Parse error for Registration");
        assert_eq!(err.info, "ID does not match rawId");
    }
}

mod assertion {
    //! assertion_test.go. Not ported: TestParseCredentialRequestResponse_NilRequest
    //! and TestParseCredentialRequestResponse_Success (`http.Request`
    //! parsing), the AppID cases of TestParsedCredentialAssertionData_Verify
    //! (ShouldFailWithAppIDNotMatchingAuthenticatorData,
    //! ShouldFailWithAppIDMatchingAuthenticatorData), and
    //! TestParsedCredentialAssertionData_VerifyDoesNotWriteBeyondAuthenticatorData,
    //! which checks Go slice capacity aliasing that Rust's `Vec` cannot have.

    use super::*;
    use apron::webauthn::protocol::{
        AuthenticatorAttachment, AuthenticatorFlags, CeremonyType, CollectedClientData,
    };

    pub(crate) const SUCCESS: &str = vector!("credential_assertion_success.json");
    const TRAILING_DATA: &str = vector!("credential_assertion_trailingData.json");

    const ID: &str = "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng";

    /// Go's `testAssertionSpecVectorNoneES256`: the W3C none ES256 test
    /// vector, with its credential public key and challenge.
    pub(crate) fn spec_vector_none_es256(
    ) -> (ParsedCredentialAssertionData, Vec<u8>, String, Vec<u8>) {
        let credential_id = hex("f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4");
        let cred_pub_key = hex("a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220");
        let challenge = URL_SAFE_NO_PAD.encode(hex(
            "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408",
        ));
        let body = assertion_body(
            &credential_id,
            &hex("bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"),
            &hex("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"),
            &hex("3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"),
            None,
        );
        let parsed = parse_credential_request_response_bytes(body.as_bytes()).expect("spec vector");
        (parsed, cred_pub_key, challenge, credential_id)
    }

    /// An authentication response body, as Go's test fixtures marshal one.
    pub(crate) fn assertion_body(
        id: &[u8],
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signature: &[u8],
        user_handle: Option<&[u8]>,
    ) -> String {
        let id = URL_SAFE_NO_PAD.encode(id);
        let user_handle = user_handle.map_or(String::new(), |h| {
            format!(r#","userHandle":"{}""#, URL_SAFE_NO_PAD.encode(h))
        });
        format!(
            r#"{{"id":"{id}","rawId":"{id}","type":"public-key","response":{{"authenticatorData":"{}","clientDataJSON":"{}","signature":"{}"{user_handle}}}}}"#,
            URL_SAFE_NO_PAD.encode(authenticator_data),
            URL_SAFE_NO_PAD.encode(client_data_json),
            URL_SAFE_NO_PAD.encode(signature),
        )
    }

    /// Go reads the body through `ParseCredentialRequestResponseBody`; the
    /// port parses the same bytes. As for registration, each field is
    /// compared in place of whole structs.
    #[test]
    fn test_parse_credential_request_response() {
        let auth_data = b64url("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ");
        let signature = b64url("MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc");
        let user_handle = b64url("0ToAAAAAAAAAAA");

        let actual = parse_credential_request_response_bytes(SUCCESS.as_bytes())
            .expect("ShouldParseCredentialAssertion");
        assert_eq!(actual.id, ID);
        assert_eq!(actual.kind, "public-key");
        assert_eq!(actual.raw_id, b64url(ID));
        assert_eq!(actual.client_extension_results.appid, None);
        assert_eq!(actual.client_extension_results.present(), ["vendorAppID"]);
        assert_eq!(
            actual.authenticator_attachment,
            AuthenticatorAttachment::default()
        );
        assert_eq!(
            actual.response.collected_client_data,
            CollectedClientData {
                kind: CeremonyType::new("webauthn.get"),
                challenge: "E4PTcIH_HfX1pC6Sigk1SC9NAlgeztN0439vi8z_c9k".into(),
                origin: "https://webauthn.io".into(),
                hint: "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
                    .into(),
                ..CollectedClientData::default()
            }
        );
        let ad = &actual.response.authenticator_data;
        assert_eq!(
            ad.rpid_hash,
            b64url("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
        );
        assert_eq!(ad.counter, 1553097241);
        assert_eq!(ad.flags, AuthenticatorFlags(0x45));
        assert_eq!(ad.att_data.aaguid, b64url("rc4AAjW8xgpkiwsl8fBVAw"));
        assert_eq!(ad.att_data.credential_id, b64url(ID));
        assert_eq!(
            cose_members(&ad.att_data.credential_public_key),
            cose_members(&b64url("pQMmIAEhWCAoCF-x0dwEhzQo-ABxHIAgr_5WL6cJceREc81oIwFn7iJYIHEHx8ZhBIE42L26-rSC_3l0ZaWEmsHAKyP9rgslApUdAQI"))
        );
        assert_eq!(actual.response.signature, signature);
        assert_eq!(actual.response.user_handle, user_handle);
        let raw = &actual.raw;
        assert_eq!((raw.id.as_str(), raw.kind.as_str()), (ID, "public-key"));
        assert_eq!(raw.raw_id.0, b64url(ID));
        assert_eq!(raw.assertion_response.authenticator_data.0, auth_data);
        assert_eq!(raw.assertion_response.signature.0, signature);
        assert_eq!(raw.assertion_response.user_handle.0, user_handle);

        let err = parse_credential_request_response_bytes(TRAILING_DATA.as_bytes())
            .expect_err("ShouldHandleTrailingData");
        assert_eq!(err.to_string(), "Parse error for Assertion");
        assert_protocol_error(
            &err,
            ErrorType::InvalidRequest,
            "Parse error for Assertion",
            "body contains trailing data",
        );
    }

    #[test]
    fn test_parse_credential_request_response_bytes() {
        let cases = [
            (
                "ShouldFailInvalidJSON",
                "not json",
                "invalid character 'o' in literal null (expecting 'u')",
            ),
            (
                "ShouldFailTrailingData",
                TRAILING_DATA,
                "body contains trailing data",
            ),
        ];
        for (name, data, info) in cases {
            let err = parse_credential_request_response_bytes(data.as_bytes()).expect_err(name);
            assert_eq!(err.to_string(), "Parse error for Assertion", "{name}");
            assert_protocol_error(
                &err,
                ErrorType::InvalidRequest,
                "Parse error for Assertion",
                info,
            );
        }
        let result =
            parse_credential_request_response_bytes(SUCCESS.as_bytes()).expect("ShouldSucceed");
        assert_eq!(result.id, ID);
    }

    /// Go calls `CredentialAssertionResponse.Parse` on a struct; the port
    /// parses the JSON of that struct.
    #[test]
    fn test_credential_assertion_response_parse_errors() {
        let cases = [
            (
                "ShouldFailMissingID",
                r#"{}"#,
                "CredentialAssertionResponse with ID missing",
            ),
            (
                "ShouldFailIDNotBase64",
                r#"{"id":"not valid base64 %%%"}"#,
                "CredentialAssertionResponse with ID not base64url encoded",
            ),
            (
                "ShouldFailBadType",
                r#"{"id":"dGVzdA","type":"bad-type"}"#,
                "CredentialAssertionResponse with bad type",
            ),
            (
                "ShouldFailRawIDMismatch",
                r#"{"id":"dGVzdA","type":"public-key","rawId":"bm90IHRlc3Q"}"#,
                "CredentialAssertionResponse with ID that does not match the rawId",
            ),
            (
                "ShouldFailIDDecodingToNoBytes",
                r#"{"id":"\r\n","type":"public-key"}"#,
                "CredentialAssertionResponse with ID that decodes to no bytes",
            ),
            (
                "ShouldFailRawIDMissing",
                r#"{"id":"dGVzdA","type":"public-key"}"#,
                "CredentialAssertionResponse with ID that does not match the rawId",
            ),
        ];
        for (name, body, want) in cases {
            let err = parse_credential_request_response_bytes(body.as_bytes()).expect_err(name);
            assert_eq!(err.to_string(), want, "{name}");
        }
    }

    #[test]
    fn test_parsed_credential_assertion_data_verify() {
        let (par, cred_pub_key, challenge, _) = spec_vector_none_es256();
        let wrong_key = hex("a5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2");
        // Name, challenge, RP ID, credential public key, expected error.
        type Case<'a> = (&'a str, &'a str, &'a str, &'a [u8], Option<&'a str>);
        let cases: [Case; 5] = [
            (
                "ShouldSucceed",
                &challenge,
                "example.org",
                &cred_pub_key,
                None,
            ),
            (
                "ShouldFailClientDataVerification",
                "wrong-challenge",
                "example.org",
                &cred_pub_key,
                Some("Error validating challenge"),
            ),
            (
                "ShouldFailAuthDataVerification",
                &challenge,
                "wrong-rp-id.example.com",
                &cred_pub_key,
                Some("Error validating the authenticator response"),
            ),
            (
                "ShouldFailInvalidPublicKey",
                &challenge,
                "example.org",
                b"invalid-key",
                Some("Error parsing the assertion public key: Unsupported Public Key Type"),
            ),
            (
                "ShouldFailSignatureVerification",
                &challenge,
                "example.org",
                &wrong_key,
                Some("Error validating the assertion signature: <nil>"),
            ),
        ];
        for (name, challenge, rp_id, credential_bytes, want) in cases {
            let result = par.verify(
                challenge,
                rp_id,
                &strings(&["https://example.org"]),
                &[],
                TopOriginVerificationMode::Explicit,
                false,
                false,
                true,
                credential_bytes,
            );
            assert_eq!(
                result.map_err(|err| err.to_string()),
                want.map_or(Ok(()), |w| Err(w.to_string())),
                "{name}"
            );
        }
    }

    #[test]
    fn test_credential_assertion_response_parse_authenticator_attachment() {
        let cases = [
            (
                "ShouldHandlePlatform",
                "platform",
                AuthenticatorAttachment::PLATFORM,
            ),
            (
                "ShouldHandleCrossPlatform",
                "cross-platform",
                AuthenticatorAttachment::CROSS_PLATFORM,
            ),
            ("ShouldHandleEmpty", "", AuthenticatorAttachment::default()),
        ];
        for (name, attachment, want) in cases {
            let data = if attachment.is_empty() {
                SUCCESS.to_string()
            } else {
                SUCCESS.replacen(
                    r#""type":"public-key","#,
                    &format!(r#""type":"public-key","authenticatorAttachment":"{attachment}","#),
                    1,
                )
            };
            let result = parse_credential_request_response_bytes(data.as_bytes()).expect(name);
            assert_eq!(result.authenticator_attachment, want, "{name}");
        }
    }

    /// Go asserts only that parsing fails; it returns the JSON error as is,
    /// which is the error asserted here.
    #[test]
    fn test_credential_assertion_response_parse_client_data_json_error() {
        let mut auth_data = vec![0u8; 32];
        auth_data.push(0x01);
        auth_data.extend_from_slice(&[0; 8]);
        let body = assertion_body(b"test", &auth_data, b"not valid json", b"", None);
        let err =
            parse_credential_request_response_bytes(body.as_bytes()).expect_err("client data");
        assert_protocol_error(
            &err,
            ErrorType::Other,
            "invalid character 'o' in literal null (expecting 'u')",
            "",
        );
    }

    #[test]
    fn test_credential_assertion_response_parse_auth_data_error() {
        let body = assertion_body(
            b"test",
            &[0x01, 0x02],
            br#"{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://example.org"}"#,
            b"",
            None,
        );
        let err = parse_credential_request_response_bytes(body.as_bytes()).expect_err("auth data");
        assert_eq!(err.to_string(), "Error unmarshalling auth data");
    }
}

mod webauthncose {
    //! webauthncose/webauthncose_test.go and webauthncose/signature_test.go.
    //! Not ported: TestOKPDisplayPublicKey (`DisplayPublicKey`),
    //! TestHasherFromCOSEAlg (`HasherFromCOSEAlg` is internal to the port),
    //! TestUnsupportedKeyMethods (the port's key enum cannot hold a bare
    //! `PublicKeyData`), TestFIDOPublicKey (FIDO U2F keys), the
    //! ShouldHandleNilKey case of TestRSAExponent (no nil key in Rust), and
    //! the `ToECDSA`, `TPMCurveID` and `DisplayPublicKey` checks of
    //! TestParsePublicKey.

    use super::*;
    use apron::webauthn::protocol::webauthncose::{
        parse_public_key, parse_rsa_public_key_data_exponent, verify_signature, Ec2PublicKeyData,
        OkpPublicKeyData, PublicKey, PublicKeyData, RsaPublicKeyData,
    };
    use rust_stdlib_crypto::{ecdsa, ed25519, elliptic};
    use rust_stdlib_derive::Deserialize;

    const ALG_EDDSA: i64 = -8;
    const ALG_ES256: i64 = -7;
    const ALG_RS256: i64 = -257;

    fn okp_key(algorithm: i64, x: Vec<u8>) -> OkpPublicKeyData {
        OkpPublicKeyData {
            public_key_data: PublicKeyData {
                key_type: 1,
                algorithm,
            },
            curve: 6,
            x_coord: x,
        }
    }

    #[test]
    fn test_okp_signature_verification() {
        let (public, private) = ed25519::generate_key().expect("generate");
        let data = b"Sample data to sign";
        let valid_sig = ed25519::sign(&private, data).expect("sign");
        let key = okp_key(ALG_EDDSA, public.0);
        assert_eq!(key.verify(data, &valid_sig), Ok(true));
        assert_eq!(key.verify(data, b"invalid"), Ok(false));
    }

    #[test]
    fn test_okp_verify_rejects_unsupported_algorithm() {
        let (public, private) = ed25519::generate_key().expect("generate");
        let data = b"Sample data to sign";
        let valid_sig = ed25519::sign(&private, data).expect("sign");
        let key = okp_key(ALG_RS256, public.0);
        let err = key.verify(data, &valid_sig).expect_err(
            "a key declaring an algorithm this library does not verify OKP keys with must not verify",
        );
        assert_eq!(err.to_string(), "OKP key has unsupported algorithm RS256");
    }

    #[test]
    fn test_p256_signature_verification() {
        let key = PublicKey::Ec2(Ec2PublicKeyData {
            public_key_data: PublicKeyData {
                key_type: 2,
                algorithm: ALG_ES256,
            },
            curve: 1,
            x_coord: hex("f739f8c77b32f4d5f13265861febd76e7a9c61a1140d296b8c16302508870316"),
            y_coord: hex("c24970ad7811ccd9da7f1b88f202bebac770663ef58ba68346186dd778200dd4"),
        });
        let valid_sig = hex("3045022053584980793ee4ec01d583f303604c4f85a7e87df3fe9551962c5ab69a5ce27b022100c801fd6186ca4681e87fbbb97c5cb659f039473995a75a9a9dffea2708d6f8fb");
        assert_eq!(verify_signature(&key, b"webauthnFTW", &valid_sig), Ok(true));
        assert_eq!(
            verify_signature(&key, b"webauthnFTL", &valid_sig),
            Ok(false)
        );
    }

    #[test]
    fn test_rsa_exponent() {
        let cases: [(&str, &[u8], Result<i64, &str>); 6] = [
            ("ShouldHandle3ByteExponent", &[0x01, 0x00, 0x01], Ok(65537)),
            (
                "ShouldHandle3ByteExponentAlt",
                &[0x01, 0x00, 0x02],
                Ok(65538),
            ),
            (
                "ShouldHandle3ByteExponentLarge",
                &[0xff, 0xff, 0xff],
                Ok(16777215),
            ),
            (
                "ShouldHandle4ByteExponent",
                &[0x01, 0x00, 0x02, 0xff],
                Ok(16777983),
            ),
            (
                "ShouldHandleZeroLength",
                &[],
                Err("invalid exponent length"),
            ),
            (
                "ShouldHandleNilExponent",
                &[],
                Err("invalid exponent length"),
            ),
        ];
        for (name, exponent, want) in cases {
            let key = RsaPublicKeyData {
                exponent: exponent.to_vec(),
                ..RsaPublicKeyData::default()
            };
            assert_eq!(
                parse_rsa_public_key_data_exponent(&key).map_err(|err| err.to_string()),
                want.map_err(str::to_string),
                "{name}"
            );
        }
    }

    #[derive(Debug, Default, Deserialize)]
    struct ParsePublicKeyVector {
        #[json("name")]
        name: String,
        #[json("attestation_object")]
        attestation_object: String,
        #[json("client_data_json")]
        client_data_json: String,
        #[json("authenticator_data")]
        authenticator_data: String,
        #[json("signature")]
        signature: String,
        #[json("key_kind")]
        key_kind: String,
        #[json("kty")]
        kty: i64,
        #[json("alg")]
        alg: i64,
        #[json("crv")]
        crv: i64,
        #[json("x")]
        x: String,
        #[json("y")]
        y: String,
        #[json("n")]
        n: String,
        #[json("e")]
        e: String,
    }

    impl ParsePublicKeyVector {
        /// The key Go's table expects, as the extraction read it from the Go
        /// struct literal.
        fn expected(&self) -> PublicKey {
            let public_key_data = PublicKeyData {
                key_type: self.kty,
                algorithm: self.alg,
            };
            match self.key_kind.as_str() {
                "EC2PublicKeyData" => PublicKey::Ec2(Ec2PublicKeyData {
                    public_key_data,
                    curve: self.crv,
                    x_coord: hex(&self.x),
                    y_coord: hex(&self.y),
                }),
                "RSAPublicKeyData" => PublicKey::Rsa(RsaPublicKeyData {
                    public_key_data,
                    modulus: hex(&self.n),
                    exponent: hex(&self.e),
                }),
                "OKPPublicKeyData" => PublicKey::Okp(OkpPublicKeyData {
                    public_key_data,
                    curve: self.crv,
                    x_coord: hex(&self.x),
                }),
                other => panic!("unexpected key kind {other}"),
            }
        }
    }

    fn parse_public_key_vectors() -> Vec<ParsePublicKeyVector> {
        rust_stdlib::encoding::json::unmarshal(vector!("parse_public_key_vectors.json").as_bytes())
            .expect("vectors")
    }

    /// Go's `MustConstructSignedData`.
    fn signed_data(client_data_json: &str, authenticator_data: &str) -> Vec<u8> {
        let mut data = hex(authenticator_data);
        data.extend_from_slice(&sha256::sum256(&hex(client_data_json)));
        data
    }

    /// The W3C test vectors, including the tpm, android-key and apple ones:
    /// only the credential public key is taken from their attestation
    /// objects, so the attestation format never runs.
    #[test]
    fn test_parse_public_key() {
        let vectors = parse_public_key_vectors();
        assert_eq!(vectors.len(), 13);
        for tc in vectors {
            let key_bytes = cose_key_from_attestation_object(&hex(&tc.attestation_object));
            let result =
                parse_public_key(&key_bytes).unwrap_or_else(|err| panic!("{}: {err}", tc.name));
            let data = signed_data(&tc.client_data_json, &tc.authenticator_data);
            assert_eq!(
                verify_signature(&result, &data, &hex(&tc.signature)),
                Ok(true),
                "{}",
                tc.name
            );
            assert_eq!(result, tc.expected(), "{}", tc.name);
        }
    }

    /// Go's `mustMarshalCOSEKey`.
    fn cose_key(kty: i64, alg: i64, extra: Vec<(i64, Value)>) -> Vec<u8> {
        let int = |n: i64| {
            if n >= 0 {
                Value::Unsigned(n as u64)
            } else {
                Value::Negative((-1 - n) as u64)
            }
        };
        let mut members = vec![(int(1), int(kty)), (int(3), int(alg))];
        members.extend(extra.into_iter().map(|(k, v)| (int(k), v)));
        cbor::marshal(&Value::Map(members))
    }

    /// Go generates fresh key material for the accept cases; the valid
    /// Ed25519 and P-256 public keys of the W3C vectors stand in for it.
    #[test]
    fn test_parse_public_key_validation() {
        let vectors = parse_public_key_vectors();
        let okp_pub = hex(&vectors[9].x);
        let ec2_x = hex(&vectors[0].x);
        let ec2_y = hex(&vectors[0].y);
        let int = |n: i64| {
            if n >= 0 {
                Value::Unsigned(n as u64)
            } else {
                Value::Negative((-1 - n) as u64)
            }
        };
        let bytes = |b: &[u8]| Value::Bytes(b.to_vec());
        let cases = [
            (
                "ShouldAcceptValidOKPKey",
                cose_key(1, ALG_EDDSA, vec![(-1, int(6)), (-2, bytes(&okp_pub))]),
                None,
            ),
            (
                "ShouldAcceptValidOKPKeyWithFullySpecifiedAlgorithm",
                cose_key(1, -19, vec![(-1, int(6)), (-2, bytes(&okp_pub))]),
                None,
            ),
            (
                "ShouldAcceptValidEC2Key",
                cose_key(
                    2,
                    ALG_ES256,
                    vec![(-1, int(1)), (-2, bytes(&ec2_x)), (-3, bytes(&ec2_y))],
                ),
                None,
            ),
            (
                "ShouldAcceptValidRSAKey",
                cose_key(
                    3,
                    ALG_RS256,
                    vec![(-1, bytes(&[0xff])), (-2, bytes(&[0x01, 0x00, 0x01]))],
                ),
                None,
            ),
            (
                "ShouldRejectOKPWithInvalidXCoordLength",
                cose_key(1, ALG_EDDSA, vec![(-1, int(6)), (-2, bytes(&[0; 16]))]),
                Some("OKP key x coordinate has invalid length 16, expected 32"),
            ),
            (
                "ShouldRejectOKPWithUnsupportedAlgorithm",
                cose_key(1, ALG_RS256, vec![(-1, int(6)), (-2, bytes(&okp_pub))]),
                Some("OKP key has unsupported algorithm RS256"),
            ),
            (
                "ShouldRejectOKPWithUnregisteredAlgorithm",
                cose_key(1, 999, vec![(-1, int(6)), (-2, bytes(&okp_pub))]),
                Some("OKP key has unsupported algorithm 999"),
            ),
            (
                "ShouldRejectEC2WithUnsupportedAlgorithm",
                cose_key(
                    2,
                    999,
                    vec![(-1, int(1)), (-2, bytes(&[0; 32])), (-3, bytes(&[0; 32]))],
                ),
                Some("Unsupported EC2 algorithm"),
            ),
            (
                "ShouldRejectEC2WithInvalidCoordLength",
                cose_key(
                    2,
                    ALG_ES256,
                    vec![(-1, int(1)), (-2, bytes(&[0; 48])), (-3, bytes(&[0; 48]))],
                ),
                Some("EC2 key x or y coordinate has invalid length"),
            ),
            (
                "ShouldRejectEC2WithOffCurvePoint",
                cose_key(
                    2,
                    ALG_ES256,
                    vec![(-1, int(1)), (-2, bytes(&[0; 32])), (-3, bytes(&[0; 32]))],
                ),
                Some("EC2 key point is not on curve"),
            ),
            (
                "ShouldRejectRSAWithEmptyModulus",
                cose_key(
                    3,
                    ALG_RS256,
                    vec![(-1, bytes(&[])), (-2, bytes(&[0x01, 0x00, 0x01]))],
                ),
                Some("RSA key contains zero or empty modulus"),
            ),
            (
                "ShouldRejectRSAWithEmptyExponent",
                cose_key(3, ALG_RS256, vec![(-1, bytes(&[0xff])), (-2, bytes(&[]))]),
                Some("RSA key contains invalid exponent: invalid exponent length"),
            ),
        ];
        for (name, input, want) in cases {
            match (parse_public_key(&input), want) {
                (Ok(key), None) => assert_eq!(
                    key.algorithm(),
                    cbor_alg(&input),
                    "{name}: the parsed key keeps its algorithm"
                ),
                (Err(err), Some(want)) => assert_eq!(err.to_string(), want, "{name}"),
                (result, want) => panic!("{name}: got {result:?}, want {want:?}"),
            }
        }
    }

    fn cbor_alg(key: &[u8]) -> i64 {
        let Value::Map(members) = cbor::unmarshal(key).expect("key") else {
            panic!("key is not a map");
        };
        members
            .iter()
            .find(|(k, _)| *k == Value::Unsigned(3))
            .and_then(|(_, v)| match *v {
                Value::Negative(n) => Some(-1 - n as i64),
                Value::Unsigned(n) => Some(n as i64),
                _ => None,
            })
            .expect("alg")
    }

    /// signature_test.go TestEC2PublicKeyDataVerifyRequiresCanonicalDER.
    #[test]
    fn test_ec2_public_key_data_verify_requires_canonical_der() {
        let private = ecdsa::generate_key(elliptic::p256()).expect("generate");
        let key = Ec2PublicKeyData {
            public_key_data: PublicKeyData {
                key_type: 2,
                algorithm: ALG_ES256,
            },
            curve: 1,
            x_coord: private.public_key.x.fill_bytes(32).expect("x"),
            y_coord: private.public_key.y.fill_bytes(32).expect("y"),
        };
        let data = b"data to sign";
        let der = ecdsa::sign_asn1(&private, &sha256::sum256(data)).expect("sign");
        assert_eq!(key.verify(data, &der), Ok(true));

        // The two INTEGERs of the signature, as `asn1.Marshal` encodes them.
        assert_eq!(der[0], 0x30);
        assert_eq!(usize::from(der[1]), der.len() - 2);
        let r_len = usize::from(der[3]);
        let minimal_r = der[2..4 + r_len].to_vec();
        let minimal_s = der[4 + r_len..].to_vec();
        let sequence = |elements: &[&[u8]]| {
            let content = elements.concat();
            assert!(content.len() < 0x80);
            [&[0x30, content.len() as u8][..], &content].concat()
        };
        let padded = |minimal: &[u8]| {
            let content = [&[0x00][..], &minimal[2..]].concat();
            [&[0x02, content.len() as u8][..], &content].concat()
        };
        let cases = [
            (
                "ShouldRejectTrailingDataAfterSignature",
                [&der[..], &[0xde, 0xad, 0xbe, 0xef]].concat(),
            ),
            (
                "ShouldRejectTrailingElementWithinSequence",
                sequence(&[&minimal_r, &minimal_s, &[0x02, 0x01, 0x7f]]),
            ),
            (
                "ShouldRejectBERPaddedR",
                sequence(&[&padded(&minimal_r), &minimal_s]),
            ),
            (
                "ShouldRejectBERPaddedS",
                sequence(&[&minimal_r, &padded(&minimal_s)]),
            ),
        ];
        for (name, have) in cases {
            assert_ne!(der, have, "{name}");
            let err = key.verify(data, &have).expect_err(name);
            assert_eq!(
                err.to_string(),
                "Signature invalid or not provided",
                "{name}"
            );
        }
    }
}

mod webauthn {
    //! The `webauthn` package tests: authenticator_test.go
    //! TestAuthenticator_UpdateCounter, and the registration_test.go and
    //! login_test.go cases for the ceremonies the port has
    //! (`BeginRegistration`, `CreateCredential`, `BeginDiscoverableLogin`,
    //! `ValidatePasskeyLogin`, `ValidateDiscoverableLogin`).
    //!
    //! The port has no `ValidateLogin` for a known user; its checks after the
    //! user lookup are the ones `ValidatePasskeyLogin` runs, so the
    //! `ValidateLogin` cases here run through `ValidatePasskeyLogin`, with the
    //! user handle set to the user's ID and the session's user ID left empty.
    //! The `BeginLogin` cases for behavior it shares with
    //! `BeginDiscoverableLogin` run through the latter.
    //!
    //! Not ported, for options or configuration the port does not have:
    //! TestWithRegistrationRelyingPartyID and TestWithLoginRelyingPartyID
    //! cases that use `WithRegistrationRelyingPartyID`,
    //! `WithRegistrationRelyingPartyName` or `WithLoginRelyingPartyID`;
    //! TestBeginRegistration_EncodeUserIDAsString and the string and int
    //! handle cases of TestBeginRegistrationUserHandleAfterOptions
    //! (`EncodeUserIDAsString`); the ShouldEncodeString case of
    //! TestEntityEncoding; TestBeginMediatedRegistration_EnforceTimeout and
    //! TestBeginLogin_EnforceTimeout (`Timeouts`);
    //! TestBeginRegistrationHintsSetAuthenticatorAttachment (hints);
    //! TestValidateFilteredCredential and
    //! TestCreateCredentialPropagatesFilteringFailure (`Filtering`);
    //! TestRegistrationOptions and TestLoginOptions cases for options the
    //! port does not have, and their Empty cases (no option applied);
    //! TestBeginRegistrationOptionError and
    //! TestBeginLoginOptionError (the port's options cannot fail);
    //! TestBeginRegistration_StoresSessionExtensions,
    //! TestCreateCredentialAcceptsSolicitedExtensionOutput,
    //! TestCreateCredentialRejectsUnhonouredCredentialProtectionPolicy and
    //! the SolicitedOutput case of TestValidateLoginExtensionOutputs
    //! (requesting extensions); TestBeginDiscoverableMediatedLogin,
    //! TestBeginMediatedLogin_NoCredentials, the ShouldSucceedMediationConditional
    //! case of TestCreateCredential_Full, and BeginLogin-only behavior
    //! (mediation, `BeginLogin`); TestSelectAuthenticator
    //! (`SelectAuthenticator`); TestValidateLogin_Errors (`ValidateLogin`'s
    //! user ID check).
    //!
    //! Not ported, out of the subset: the MDS cases of TestCreateCredential_Full
    //! and TestValidateLogin_Full; TestCreateCredentialOpaqueOrigin,
    //! TestValidateLoginOpaqueOrigin, and the opaque origin cases of
    //! TestCreateCredentialBoundOrigin and TestValidateLoginBoundOrigin;
    //! TestBeginRegistrationAppIDExcludePruning*, TestBeginLoginAppIDPruning*,
    //! TestBeginDiscoverableLoginAppIDPruning and
    //! TestValidateLoginAppIDFromSessionReplacesRPID (AppID);
    //! TestRegistration_FinishRegistrationFailure, TestFinishRegistration_Success,
    //! TestLogin_FinishLoginFailure, TestFinishDiscoverableLogin_Failure and
    //! TestFinishPasskeyLogin_Failure (`http.Request` parsing; the success
    //! cases of the Finish* helpers are ported as parse then validate);
    //! TestAuthenticator_Msgp* and TestAuthenticator_DecodeMsgInvalidTypes
    //! (msgp); and the `ValidateLogin` subtests of
    //! TestFinishLoginFailureSessionChallenge.

    use super::assertion::{assertion_body, spec_vector_none_es256, SUCCESS as ASSERTION_SUCCESS};
    use super::*;
    use apron::webauthn::protocol::{
        AuthenticationExtensionsClientOutputs, AuthenticatorAttachment, AuthenticatorFlags,
        AuthenticatorSelection, AuthenticatorTransport, CredentialDescriptor,
        PublicKeyCredentialCreationOptions, PublicKeyCredentialRequestOptions,
        ResidentKeyRequirement, UrlEncodedBase64, UserEntity, UserVerificationRequirement,
    };
    use apron::webauthn::{
        with_authenticator_selection, with_challenge, with_exclusions, with_login_origin,
        with_registration_origin, with_resident_key_requirement, with_user_verification,
        Authenticator, Config, Credential, CredentialFlags, RegistrationOption, SessionData, User,
        WebAuthn,
    };
    use rust_stdlib::encoding::json::{self, v2, Bytes};
    use rust_stdlib::time;

    /// Go's `testUserID`.
    const TEST_USER_ID: &[u8] = b"test-user-id";

    /// Go's `defaultUser`.
    #[derive(Clone, Default)]
    struct TestUser {
        id: Vec<u8>,
        credentials: Vec<Credential>,
    }

    impl User for TestUser {
        fn webauthn_id(&self) -> &[u8] {
            &self.id
        }
        fn webauthn_name(&self) -> String {
            String::new()
        }
        fn webauthn_display_name(&self) -> String {
            String::new()
        }
        fn webauthn_credentials(&self) -> &[Credential] {
            &self.credentials
        }
    }

    fn user(id: &[u8]) -> TestUser {
        TestUser {
            id: id.to_vec(),
            credentials: Vec::new(),
        }
    }

    fn user_with(id: &[u8], credentials: Vec<Credential>) -> TestUser {
        TestUser {
            id: id.to_vec(),
            credentials,
        }
    }

    fn credential(id: &[u8], public_key: &[u8], flags: u8) -> Credential {
        Credential {
            id: Bytes(id.to_vec()),
            public_key: Bytes(public_key.to_vec()),
            flags: CredentialFlags::new(AuthenticatorFlags(flags)),
            ..Credential::default()
        }
    }

    const UP: u8 = AuthenticatorFlags::USER_PRESENT;
    const UV: u8 = AuthenticatorFlags::USER_VERIFIED;
    const BE: u8 = AuthenticatorFlags::BACKUP_ELIGIBLE;
    const BS: u8 = AuthenticatorFlags::BACKUP_STATE;
    const AT: u8 = AuthenticatorFlags::ATTESTED_CREDENTIAL_DATA;

    fn config(rpid: &str, display_name: &str, origins: &[&str]) -> Config {
        Config {
            rpid: rpid.into(),
            rp_display_name: display_name.into(),
            rp_origins: strings(origins),
        }
    }

    /// Go's `New`.
    fn new(config: Config) -> WebAuthn {
        WebAuthn::new(config).expect("valid configuration")
    }

    /// Go's `&WebAuthn{Config: ...}`, which skips `New`.
    fn unvalidated(rpid: &str, origins: &[&str]) -> WebAuthn {
        WebAuthn {
            config: config(rpid, "", origins),
        }
    }

    fn expired() -> time::Time {
        time::now().add(-time::HOUR)
    }

    fn es256() -> Vec<apron::webauthn::protocol::CredentialParameter> {
        params(&[-7])
    }

    const REG_NONE_ES256_ATTESTATION_OBJECT: &str = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220";
    const REG_NONE_ES256_CLIENT_DATA_JSON: &str = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d";
    const REG_NONE_ES256_CREDENTIAL_ID: &str =
        "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4";
    const REG_NONE_ES256_CHALLENGE: &str =
        "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130";
    const RP_ID_HASH: &str = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5";

    /// Go's `testRegistrationSpecVectorNoneES256Flags`: the W3C none ES256
    /// registration with its flags byte replaced. Returns the body, the
    /// challenge and the credential ID.
    fn registration_none_es256_flags(flags: u8) -> (String, String, Vec<u8>) {
        let attestation_object = REG_NONE_ES256_ATTESTATION_OBJECT.replacen(
            &format!("{RP_ID_HASH}59"),
            &format!("{RP_ID_HASH}{flags:02x}"),
            1,
        );
        assert!(attestation_object.contains(&format!("{RP_ID_HASH}{flags:02x}")));
        registration_body(&attestation_object, &hex(REG_NONE_ES256_CLIENT_DATA_JSON))
    }

    fn registration_body(
        attestation_object: &str,
        client_data_json: &[u8],
    ) -> (String, String, Vec<u8>) {
        let credential_id = hex(REG_NONE_ES256_CREDENTIAL_ID);
        let body = creation_body(&credential_id, client_data_json, &hex(attestation_object));
        let challenge = URL_SAFE_NO_PAD.encode(hex(REG_NONE_ES256_CHALLENGE));
        (body, challenge, credential_id)
    }

    /// Go's `testRegistrationSpecVectorNoneES256`: the flags as published,
    /// UP, BE, BS and AT.
    fn registration_none_es256() -> (String, String, Vec<u8>) {
        registration_none_es256_flags(UP | BE | BS | AT)
    }

    /// Go's `testRegistrationSpecVectorNoneES256Origin`. Go re-marshals the
    /// client data with its keys sorted; the origin is replaced in place.
    fn registration_none_es256_origin(origin: &str) -> (String, String, Vec<u8>) {
        let client_data = String::from_utf8(hex(REG_NONE_ES256_CLIENT_DATA_JSON)).unwrap();
        let client_data = client_data.replacen(
            r#""origin":"https://example.org""#,
            &format!(r#""origin":"{origin}""#),
            1,
        );
        registration_body(REG_NONE_ES256_ATTESTATION_OBJECT, client_data.as_bytes())
    }

    /// Go's `testRegistrationSpecVectorPackedSelfES256`.
    fn registration_packed_self_es256() -> (String, String, Vec<u8>) {
        let credential_id = hex("455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c");
        let body = creation_body(
            &credential_id,
            &hex("7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d"),
            &hex("a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2"),
        );
        let challenge = URL_SAFE_NO_PAD.encode(hex(
            "7869c2b772d4b58eba9378cf8f29e26cf935aa77df0da89fa99c0bdc0a76f7e5",
        ));
        (body, challenge, credential_id)
    }

    fn parse_registration(body: &str) -> apron::webauthn::protocol::ParsedCredentialCreationData {
        parse_credential_creation_response_bytes(body.as_bytes()).expect("parse registration")
    }

    /// Go's `newRegistrationFixture`.
    fn registration_fixture() -> (
        WebAuthn,
        SessionData,
        apron::webauthn::protocol::ParsedCredentialCreationData,
    ) {
        let (body, challenge, _) = registration_none_es256();
        let session = SessionData {
            challenge,
            user_id: TEST_USER_ID.to_vec(),
            cred_params: es256(),
            ..SessionData::default()
        };
        (
            unvalidated("example.org", &["https://example.org"]),
            session,
            parse_registration(&body),
        )
    }

    /// Go's `testLoginSpecVectorNoneES256`, with the user handle the
    /// `ValidateLogin` cases leave to the session.
    fn login_none_es256_with_handle() -> (ParsedCredentialAssertionData, Vec<u8>, String, Vec<u8>) {
        let (mut parsed, key, challenge, id) = spec_vector_none_es256();
        parsed.response.user_handle = TEST_USER_ID.to_vec();
        (parsed, key, challenge, id)
    }

    fn passkey_login(
        w: &WebAuthn,
        user: &TestUser,
        session: &SessionData,
        parsed: &ParsedCredentialAssertionData,
    ) -> Result<Credential, Error> {
        w.validate_passkey_login(|_, _| Ok::<_, String>(user), session, parsed)
            .map(|(_, credential)| credential)
    }

    // authenticator_test.go

    #[test]
    fn test_authenticator_update_counter() {
        let cases = [
            ("IncreasedCounter", 1, 2, false),
            ("UnchangedCounter", 1, 1, true),
            ("DecreasedCounter", 2, 1, true),
            ("ZeroCounter", 0, 0, false),
            ("CounterReturnedToZero", 1, 0, true),
        ];
        for (name, sign_count, auth_data_count, want) in cases {
            let mut authenticator = Authenticator {
                aaguid: Bytes(vec![0; 16]),
                sign_count,
                clone_warning: false,
                ..Authenticator::default()
            };
            authenticator.update_counter(auth_data_count);
            assert_eq!(authenticator.clone_warning, want, "{name}");
            let expected_count = if want { sign_count } else { auth_data_count };
            assert_eq!(authenticator.sign_count, expected_count, "{name}");
        }
    }

    // registration_test.go

    #[test]
    fn test_with_registration_relying_party_id() {
        let w = new(config(
            "example.com",
            "Test Display Name",
            &["https://example.com"],
        ));
        let (creation, _) = w
            .begin_registration(&user(TEST_USER_ID), vec![])
            .expect("OptionDefinedInConfig");
        assert_eq!(creation.response.relying_party.id, "example.com");
        assert_eq!(creation.response.relying_party.name, "Test Display Name");

        // Go names the RP with WithRegistrationRelyingPartyName; the port
        // takes the name from the configuration.
        let w = new(config("", "Test Display Name", &["https://example.com"]));
        let err = w
            .begin_registration(&user(TEST_USER_ID), vec![])
            .expect_err("OptionIDNotDefined");
        assert_eq!(err.to_string(), "error generating credential creation: the relying party id must be provided via the configuration or a functional option for a creation");
    }

    #[test]
    fn test_entity_encoding() {
        let entity = UserEntity {
            id: UrlEncodedBase64(b"abc".to_vec()),
            ..UserEntity::default()
        };
        let data = v2::marshal(&entity, &[]).expect("ShouldEncodeBase64");
        assert_eq!(
            String::from_utf8(data).unwrap(),
            r#"{"name":"","displayName":"","id":"YWJj"}"#
        );
    }

    #[test]
    fn test_create_credential_errors() {
        let w = unvalidated("example.com", &["https://example.com"]);
        let cases = [
            (
                "ShouldFailUserIDMismatch",
                SessionData {
                    user_id: b"456".to_vec(),
                    ..SessionData::default()
                },
                "ID mismatch for User and Session",
            ),
            (
                "ShouldFailSessionExpired",
                SessionData {
                    user_id: b"123".to_vec(),
                    expires: expired(),
                    ..SessionData::default()
                },
                "Session has Expired",
            ),
        ];
        for (name, session, want) in cases {
            let err = w
                .create_credential(&user(b"123"), &session, Default::default())
                .expect_err(name);
            assert_eq!(err.to_string(), want, "{name}");
        }
    }

    /// Go sets the discouraged user verification in the configuration's
    /// `AuthenticatorSelection`; the port sets it with
    /// `WithAuthenticatorSelection`.
    #[test]
    fn test_begin_registration_timeouts() {
        let w = new(config(
            "example.com",
            "Test Display Name",
            &["https://example.com"],
        ));
        let (creation, _) = w
            .begin_registration(&user(b"123"), vec![])
            .expect("ShouldUseDefaultTimeout");
        assert_eq!(creation.response.timeout, 300000);

        let discouraged = with_authenticator_selection(AuthenticatorSelection {
            user_verification: UserVerificationRequirement::DISCOURAGED,
            ..AuthenticatorSelection::default()
        });
        let (creation, _) = w
            .begin_registration(&user(b"123"), vec![discouraged])
            .expect("ShouldUseUVDTimeout");
        assert_eq!(creation.response.timeout, 120000);
    }

    /// Go's `withTestChallenge`.
    fn with_test_challenge(challenge: Vec<u8>) -> RegistrationOption {
        Box::new(move |o: &mut PublicKeyCredentialCreationOptions| {
            o.challenge = UrlEncodedBase64(challenge)
        })
    }

    /// The success cases of TestBeginMediatedRegistration_ChallengeLength,
    /// through `BeginRegistration` (Go's default mediation).
    #[test]
    fn test_begin_mediated_registration_challenge_length() {
        let w = new(config(
            "example.com",
            "Test Display Name",
            &["https://example.com"],
        ));
        let cases = [
            ("ShouldSucceedWithDefaultChallenge", None, 32),
            (
                "ShouldSucceedSixteenByteChallenge",
                Some(vec![0xab; 16]),
                16,
            ),
            (
                "ShouldSucceedThirtyTwoByteChallenge",
                Some(vec![0xab; 32]),
                32,
            ),
        ];
        for (name, challenge, want_len) in cases {
            let opts: Vec<RegistrationOption> =
                challenge.map(with_test_challenge).into_iter().collect();
            let (creation, session) = w.begin_registration(&user(b"123"), opts).expect(name);
            assert_eq!(creation.response.challenge.0.len(), want_len, "{name}");
            assert_eq!(
                creation.response.challenge.encode(),
                session.challenge,
                "{name}"
            );
        }
    }

    /// The failure cases of TestBeginMediatedRegistration_ChallengeLength.
    #[test]
    fn test_begin_mediated_registration_challenge_length_too_short() {
        let w = new(config(
            "example.com",
            "Test Display Name",
            &["https://example.com"],
        ));
        let cases = [
            ("ShouldFailNilChallenge", Vec::new()),
            ("ShouldFailEmptyChallenge", Vec::new()),
            ("ShouldFailEightByteChallenge", vec![0xab; 8]),
            ("ShouldFailFifteenByteChallenge", vec![0xab; 15]),
        ];
        for (name, challenge) in cases {
            let err = w
                .begin_registration(&user(b"123"), vec![with_test_challenge(challenge)])
                .map(|_| ())
                .expect_err(name);
            assert_eq!(
                err.to_string(),
                "error generating credential creation: the challenge must be at least 16 bytes",
                "{name}"
            );
        }
    }

    #[test]
    fn test_registration_options() {
        let exclusions = vec![CredentialDescriptor {
            kind: CredentialType::PUBLIC_KEY,
            credential_id: UrlEncodedBase64(b"123".to_vec()),
            transport: vec![AuthenticatorTransport::HYBRID],
            ..CredentialDescriptor::default()
        }];
        let selection = AuthenticatorSelection {
            authenticator_attachment: AuthenticatorAttachment::CROSS_PLATFORM,
            require_resident_key: Some(true),
            resident_key: ResidentKeyRequirement::REQUIRED,
            user_verification: UserVerificationRequirement::REQUIRED,
        };
        let cases: [(&str, RegistrationOption, PublicKeyCredentialCreationOptions); 4] = [
            (
                "Exclusions",
                with_exclusions(exclusions.clone()),
                PublicKeyCredentialCreationOptions {
                    credential_exclude_list: exclusions,
                    ..PublicKeyCredentialCreationOptions::default()
                },
            ),
            (
                "Selections",
                with_authenticator_selection(selection.clone()),
                PublicKeyCredentialCreationOptions {
                    authenticator_selection: selection,
                    ..PublicKeyCredentialCreationOptions::default()
                },
            ),
            (
                "ResidentKeyRequirementRequired",
                with_resident_key_requirement(ResidentKeyRequirement::REQUIRED),
                PublicKeyCredentialCreationOptions {
                    authenticator_selection: AuthenticatorSelection {
                        require_resident_key: Some(true),
                        resident_key: ResidentKeyRequirement::REQUIRED,
                        ..AuthenticatorSelection::default()
                    },
                    ..PublicKeyCredentialCreationOptions::default()
                },
            ),
            (
                "ResidentKeyRequirementPreferred",
                with_resident_key_requirement(ResidentKeyRequirement::PREFERRED),
                PublicKeyCredentialCreationOptions {
                    authenticator_selection: AuthenticatorSelection {
                        require_resident_key: Some(false),
                        resident_key: ResidentKeyRequirement::PREFERRED,
                        ..AuthenticatorSelection::default()
                    },
                    ..PublicKeyCredentialCreationOptions::default()
                },
            ),
        ];
        for (name, opt, want) in cases {
            let mut have = PublicKeyCredentialCreationOptions::default();
            opt(&mut have);
            assert_eq!(have, want, "{name}");
        }
    }

    #[test]
    fn test_create_credential_full() {
        let cases = [
            (
                "ShouldSucceedNoneFormat",
                registration_none_es256(),
                None,
                Ok(("none", "none")),
            ),
            (
                "ShouldSucceedPackedSelfFormat",
                registration_packed_self_es256(),
                None,
                Ok(("basic_surrogate", "packed")),
            ),
            (
                "ShouldFailVerifyError",
                registration_none_es256(),
                Some("d3JvbmctY2hhbGxlbmdlLXdyb25nLWNoYWxsZW5nZSE"),
                Err("Error validating challenge"),
            ),
        ];
        for (name, (body, challenge, credential_id), challenge_override, want) in cases {
            let parsed = parse_registration(&body);
            let w = unvalidated("example.org", &["https://example.org"]);
            let session = SessionData {
                challenge: challenge_override.map_or(challenge, str::to_string),
                user_id: TEST_USER_ID.to_vec(),
                cred_params: es256(),
                ..SessionData::default()
            };
            let result = w.create_credential(&user(TEST_USER_ID), &session, parsed);
            match want {
                Ok((attestation_type, attestation_format)) => {
                    let credential = result.expect(name);
                    assert_eq!(credential.id.0, credential_id, "{name}");
                    assert_eq!(credential.attestation_type, attestation_type, "{name}");
                    assert_eq!(credential.attestation_format, attestation_format, "{name}");
                }
                Err(text) => assert_eq!(result.expect_err(name).to_string(), text, "{name}"),
            }
        }
    }

    #[test]
    fn test_create_credential_uses_session_relying_party_id() {
        let (body, challenge, credential_id) = registration_none_es256();
        let w = unvalidated("example.com", &["https://example.org"]);
        let session = SessionData {
            challenge,
            relying_party_id: "example.org".into(),
            user_id: TEST_USER_ID.to_vec(),
            cred_params: es256(),
            ..SessionData::default()
        };
        let credential = w
            .create_credential(&user(TEST_USER_ID), &session, parse_registration(&body))
            .expect("session RP ID");
        assert_eq!(credential.id.0, credential_id);
    }

    #[test]
    fn test_create_credential_rejects_backup_state_without_backup_eligibility() {
        let (body, challenge, _) = registration_none_es256_flags(UP | BS | AT);
        let w = unvalidated("example.org", &["https://example.org"]);
        let session = SessionData {
            challenge,
            user_id: TEST_USER_ID.to_vec(),
            cred_params: es256(),
            ..SessionData::default()
        };
        let err = w
            .create_credential(&user(TEST_USER_ID), &session, parse_registration(&body))
            .expect_err("BS without BE");
        assert_eq!(
            err.to_string(),
            "Backup State Flag is true but Backup Eligible flag is false which is invalid"
        );
    }

    #[test]
    fn test_begin_registration_user_id_length() {
        let w = new(config(
            "example.com",
            "Test Display Name",
            &["https://example.com"],
        ));
        let cases = [
            ("ShouldRejectEmpty", Vec::new(), Some("error generating credential creation: the user id must be between 1 and 64 bytes but it has a length of 0")),
            ("ShouldAcceptMinimum", b"a".to_vec(), None),
            ("ShouldAcceptMaximum", b"a".repeat(64), None),
            ("ShouldRejectAboveMaximum", b"a".repeat(65), Some("error generating credential creation: the user id must be between 1 and 64 bytes but it has a length of 65")),
        ];
        for (name, id, want) in cases {
            let result = w.begin_registration(&user(&id), vec![]);
            match want {
                None => assert_eq!(result.expect(name).1.user_id, id, "{name}"),
                Some(text) => assert_eq!(
                    result.map(|_| ()).expect_err(name).to_string(),
                    text,
                    "{name}"
                ),
            }
        }
    }

    #[test]
    fn test_begin_registration_user_handle_after_options() {
        let with_user_handle = |id: &[u8]| -> RegistrationOption {
            let id = id.to_vec();
            Box::new(move |o: &mut PublicKeyCredentialCreationOptions| {
                o.user.id = UrlEncodedBase64(id)
            })
        };
        let w = new(config(
            "example.com",
            "Test Display Name",
            &["https://example.com"],
        ));
        let cases = [
            (
                "ShouldRejectAnEmptyHandleSetByAnOption",
                Some(with_user_handle(b"")),
                Err("error generating credential creation: the user id must be between 1 and 64 bytes but it has a length of 0"),
            ),
            (
                "ShouldRejectAnOverlengthHandleSetByAnOption",
                Some(with_user_handle(&b"a".repeat(65))),
                Err("error generating credential creation: the user id must be between 1 and 64 bytes but it has a length of 65"),
            ),
            (
                "ShouldSendAHandleSetByAnOptionButRecordTheUsersInTheSession",
                Some(with_user_handle(b"replacement")),
                Ok(&b"replacement"[..]),
            ),
            ("ShouldRecordTheUsersHandleWithoutAnOption", None, Ok(TEST_USER_ID)),
        ];
        for (name, opt, want) in cases {
            let result = w.begin_registration(&user(TEST_USER_ID), opt);
            match want {
                Ok(entity) => {
                    let (creation, session) = result.expect(name);
                    assert_eq!(creation.response.user.id.0, entity, "{name}");
                    assert_eq!(session.user_id, TEST_USER_ID, "{name}");
                }
                Err(text) => assert_eq!(
                    result.map(|_| ()).expect_err(name).to_string(),
                    text,
                    "{name}"
                ),
            }
        }
    }

    #[test]
    fn test_begin_registration_origin() {
        let w = new(config(
            "example.com",
            "Test",
            &["https://a.example.com", "https://b.example.com"],
        ));
        let cases = [
            ("ShouldNotBindAnOriginWhenTheOptionIsNotSupplied", None, Ok("")),
            ("ShouldBindAConfiguredOrigin", Some("https://b.example.com"), Ok("https://b.example.com")),
            (
                "ShouldBindAConfiguredOriginWithAnExplicitDefaultPort",
                Some("https://b.example.com:443"),
                Ok("https://b.example.com:443"),
            ),
            (
                "ShouldRejectAnOriginWhichIsNotConfigured",
                Some("https://c.example.com"),
                Err("error generating credential creation: the ceremony origin 'https://c.example.com' must be one of the origins in the 'RPOrigins' configuration"),
            ),
            (
                // Go also configures the origin in RPOpaqueOrigins; the port
                // has none and rejects an opaque origin with the same error.
                "ShouldRejectAnOpaqueOriginEvenWhenItIsConfigured",
                Some("android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"),
                Err("error generating credential creation: the ceremony origin 'android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk' can't be bound as it's opaque and an opaque origin is only conveyed in the ceremony response"),
            ),
        ];
        for (name, origin, want) in cases {
            let opts: Vec<RegistrationOption> =
                origin.map(with_registration_origin).into_iter().collect();
            let result = w.begin_registration(&user(TEST_USER_ID), opts);
            match want {
                Ok(origin) => assert_eq!(result.expect(name).1.origin, origin, "{name}"),
                Err(text) => assert_eq!(
                    result.map(|_| ()).expect_err(name).to_string(),
                    text,
                    "{name}"
                ),
            }
        }
    }

    #[test]
    fn test_create_credential_bound_origin() {
        let cases = [
            ("ShouldAcceptTheBoundOrigin", "https://example.org", None),
            (
                "ShouldAcceptAnyConfiguredOriginWhenTheSessionIsNotBound",
                "",
                None,
            ),
            (
                "ShouldRejectAnotherConfiguredOriginWhenTheSessionIsBound",
                "https://other.example.org",
                Some("Error validating origin"),
            ),
        ];
        for (name, session_origin, want) in cases {
            let (body, challenge, credential_id) = registration_none_es256();
            let w = unvalidated(
                "example.org",
                &["https://example.org", "https://other.example.org"],
            );
            let session = SessionData {
                challenge,
                origin: session_origin.into(),
                user_id: TEST_USER_ID.to_vec(),
                cred_params: es256(),
                ..SessionData::default()
            };
            let result =
                w.create_credential(&user(TEST_USER_ID), &session, parse_registration(&body));
            match want {
                None => assert_eq!(result.expect(name).id.0, credential_id, "{name}"),
                Some(text) => assert_eq!(result.expect_err(name).to_string(), text, "{name}"),
            }
        }
        // testRegistrationSpecVectorNoneES256Origin, which only Go's opaque
        // origin case uses: a client data origin outside the configured ones.
        let (body, challenge, _) = registration_none_es256_origin("https://elsewhere.example.org");
        let w = unvalidated("example.org", &["https://example.org"]);
        let session = SessionData {
            challenge,
            user_id: TEST_USER_ID.to_vec(),
            cred_params: es256(),
            ..SessionData::default()
        };
        let err = w
            .create_credential(&user(TEST_USER_ID), &session, parse_registration(&body))
            .expect_err("unconfigured origin");
        assert_eq!(
            err.info,
            "Expected Values: [https://example.org], Received: https://elsewhere.example.org"
        );
    }

    /// Go sets the output on the parsed response; here the client returns it
    /// in the registration body.
    #[test]
    fn test_create_credential_rejects_unsolicited_extension_output() {
        let (w, session, _) = registration_fixture();
        let (body, _, _) = registration_none_es256();
        let body = body.replacen(
            r#""type":"public-key","#,
            r#""type":"public-key","clientExtensionResults":{"credProps":{"rk":true}},"#,
            1,
        );
        let err = w
            .create_credential(&user(TEST_USER_ID), &session, parse_registration(&body))
            .expect_err("unsolicited credProps");
        assert_eq!(
            err.to_string(),
            r#"Error validating the client extension outputs: Client returned the "credProps" extension output which was not requested"#
        );
        // The fixture itself, with no outputs, registers.
        let (w, session, parsed) = registration_fixture();
        let credential = w
            .create_credential(&user(TEST_USER_ID), &session, parsed)
            .expect("no outputs");
        assert_eq!(credential.id.0, hex(REG_NONE_ES256_CREDENTIAL_ID));
    }

    #[test]
    fn test_begin_mediated_registration_rejects_invalid_config() {
        let w = WebAuthn {
            config: Config::default(),
        };
        let err = w
            .begin_registration(&user(TEST_USER_ID), vec![])
            .map(|_| ())
            .expect_err("empty configuration");
        assert!(
            err.to_string()
                .contains("error occurred validating the configuration"),
            "{err}"
        );
        // Go's lazy validation also rejects a configuration with an RP ID and
        // name but no origins (checked against go-webauthn v0.18.2).
        let w = WebAuthn {
            config: config("example.com", "x", &[]),
        };
        let err = w
            .begin_registration(&user(TEST_USER_ID), vec![])
            .map(|_| ())
            .expect_err("no origins");
        assert_eq!(err.to_string(), "error occurred validating the configuration: must provide at least one value to the 'RPOrigins' field");
    }

    #[test]
    fn test_create_credential_failure_session_challenge() {
        let w = WebAuthn {
            config: config("webauthn.io", "test_rp", &["https://webauthn.io"]),
        };
        let user_handle = b"0ToAAAAAAAAAAA";
        let cases = [
            (
                "ShouldFailEmpty",
                "",
                "The challenge must be at least 16 bytes but it has a length of 0",
            ),
            (
                "ShouldFailShort",
                "d3JvbmctY2hhbGxlbmdl",
                "The challenge must be at least 16 bytes but it has a length of 15",
            ),
            (
                "ShouldFailInvalid",
                "not base64url!",
                "The challenge could not be decoded: illegal base64 data at input byte 3",
            ),
        ];
        for (name, challenge, info) in cases {
            let session = SessionData {
                user_id: user_handle.to_vec(),
                challenge: challenge.into(),
                ..SessionData::default()
            };
            let err = w
                .create_credential(&user(user_handle), &session, Default::default())
                .expect_err(name);
            assert_protocol_error(
                &err,
                ErrorType::InvalidRequest,
                "Session has an invalid challenge",
                info,
            );
        }
    }

    // login_test.go

    #[test]
    fn test_with_login_relying_party_id() {
        let w = new(config(
            "example.com",
            "Test Display Name",
            &["https://example.com"],
        ));
        let (assertion, _) = w
            .begin_discoverable_login(vec![])
            .expect("OptionDefinedInConfig");
        assert_eq!(assertion.response.relying_party_id, "example.com");

        let err = new(config("", "", &["https://example.com"]))
            .begin_discoverable_login(vec![])
            .map(|_| ())
            .expect_err("OptionIDNotDefined");
        assert_eq!(err.to_string(), "error generating assertion: the relying party id must be provided via the configuration or a functional option for a login");

        let err = w
            .begin_discoverable_login(vec![with_challenge(b"1234567890".to_vec())])
            .map(|_| ())
            .expect_err("TooShortWithChallengeOption");
        assert_eq!(
            err.to_string(),
            "error generating assertion: the challenge must be at least 16 bytes"
        );

        let (assertion, _) = w
            .begin_discoverable_login(vec![with_challenge(
                b"00000000000000000000000000000000".to_vec(),
            )])
            .expect("WithChallengeOption");
        assert_eq!(assertion.response.relying_party_id, "example.com");
        assert_eq!(
            assertion.response.challenge.encode(),
            "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA"
        );
    }

    /// TestFinishLoginFailure, TestFinishLoginFailureCredentialOwnedButNotAllowedInSession
    /// and TestFinishLoginFailureCredentialNotOwned: the allowed credential
    /// checks, after parsing the body Go's `FinishLogin` reads.
    #[test]
    fn test_finish_login_failure() {
        const ID_ONE: &str =
            "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng";
        const ID_TWO: &str =
            "AI6D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng";
        let user_handle = b64url("0ToAAAAAAAAAAA");
        let key = b64url("pQMmIAEhWCAoCF-x0dwEhzQo-ABxHIAgr_5WL6cJceREc81oIwFn7iJYIHEHx8ZhBIE42L26-rSC_3l0ZaWEmsHAKyP9rgslApUdAQI");
        let stored = |id: &str| Credential {
            authenticator: Authenticator {
                aaguid: Bytes(b64url("rc4AAjW8xgpkiwsl8fBVAw")),
                ..Authenticator::default()
            },
            ..credential(&b64url(id), &key, 0)
        };
        let cases = [
            (
                "TestFinishLoginFailure",
                vec![stored(ID_ONE)],
                vec![b"test".to_vec(), b64url(ID_ONE)],
                ID_ONE,
                "User does not own all credentials from the allowed credential list",
            ),
            (
                "TestFinishLoginFailureCredentialOwnedButNotAllowedInSession",
                vec![stored(ID_ONE), stored(ID_TWO)],
                vec![b64url(ID_ONE)],
                ID_TWO,
                "The credential ID provided is not in the sessions allowed credential list",
            ),
            (
                "TestFinishLoginFailureCredentialNotOwned",
                vec![stored(ID_ONE)],
                vec![b64url(ID_ONE)],
                ID_TWO,
                "The credential ID provided is not owned by the user",
            ),
        ];
        let w = WebAuthn {
            config: config("webauthn.io", "test_rp", &["https://webauthn.io"]),
        };
        for (name, credentials, allowed, response_id, want) in cases {
            let body = ASSERTION_SUCCESS.replace(ID_ONE, response_id);
            let parsed = parse_credential_request_response_bytes(body.as_bytes()).expect(name);
            let session = SessionData {
                challenge: "E4PTcIH_HfX1pC6Sigk1SC9NAlgeztN0439vi8z_c9k".into(),
                allowed_credential_ids: allowed,
                ..SessionData::default()
            };
            let user = user_with(&user_handle, credentials);
            let err = passkey_login(&w, &user, &session, &parsed).expect_err(name);
            assert_protocol_error(&err, ErrorType::InvalidRequest, want, "");
        }
    }

    #[test]
    fn test_begin_discoverable_login() {
        let w = new(config(
            "example.com",
            "Test Display Name",
            &["https://example.com"],
        ));
        let cases = [
            (
                "ShouldSucceed",
                None,
                UserVerificationRequirement::default(),
            ),
            (
                "ShouldSucceedWithOpts",
                Some(UserVerificationRequirement::REQUIRED),
                UserVerificationRequirement::REQUIRED,
            ),
        ];
        for (name, uv, want_uv) in cases {
            let opts: Vec<_> = uv.map(with_user_verification).into_iter().collect();
            let (assertion, session) = w.begin_discoverable_login(opts).expect(name);
            assert_eq!(assertion.response.relying_party_id, "example.com", "{name}");
            assert!(session.user_id.is_empty(), "{name}");
            assert!(session.allowed_credential_ids.is_empty(), "{name}");
            assert_eq!(session.user_verification, want_uv, "{name}");
        }
    }

    /// Through `BeginDiscoverableLogin`, which shares the timeout default
    /// with `BeginLogin`. Go sets the discouraged user verification in the
    /// configuration; the port sets it with `WithUserVerification`.
    #[test]
    fn test_begin_login_timeouts() {
        let w = new(config(
            "example.com",
            "Test Display Name",
            &["https://example.com"],
        ));
        let (assertion, _) = w
            .begin_discoverable_login(vec![])
            .expect("ShouldUseDefaultTimeout");
        assert_eq!(assertion.response.timeout, 300000);
        let (assertion, _) = w
            .begin_discoverable_login(vec![with_user_verification(
                UserVerificationRequirement::DISCOURAGED,
            )])
            .expect("ShouldUseUVDTimeout");
        assert_eq!(assertion.response.timeout, 120000);
    }

    /// Not ported: ShouldFailHandlerReturnsNilUser (the handler returns a
    /// user, not a nullable pointer).
    #[test]
    fn test_validate_passkey_login_errors() {
        let w = unvalidated("example.com", &["https://example.com"]);
        let parsed_with = |user_handle: &[u8]| {
            let mut parsed = ParsedCredentialAssertionData {
                raw_id: b"cred-id".to_vec(),
                ..ParsedCredentialAssertionData::default()
            };
            parsed.response.user_handle = user_handle.to_vec();
            parsed
        };
        let challenge = "E4PTcIH_HfX1pC6Sigk1SC9NAlgeztN0439vi8z_c9k";
        let cases = [
            (
                "ShouldFailSessionNotDiscoverable",
                SessionData {
                    user_id: b"123".to_vec(),
                    ..SessionData::default()
                },
                ParsedCredentialAssertionData::default(),
                "Session was not initiated as a client-side discoverable login",
            ),
            (
                "ShouldFailSessionExpired",
                SessionData {
                    expires: expired(),
                    ..SessionData::default()
                },
                ParsedCredentialAssertionData::default(),
                "Session has Expired",
            ),
            (
                "ShouldFailBlankUserHandle",
                SessionData {
                    challenge: challenge.into(),
                    ..SessionData::default()
                },
                parsed_with(b""),
                "Client-side Discoverable Assertion was attempted with a blank User Handle",
            ),
            (
                "ShouldFailHandlerError",
                SessionData {
                    challenge: challenge.into(),
                    ..SessionData::default()
                },
                parsed_with(b"user-handle"),
                "Failed to lookup Client-side Discoverable Credential: user not found",
            ),
        ];
        for (name, session, parsed, want) in cases {
            let err = w
                .validate_passkey_login(
                    |_, _| Err::<TestUser, _>("user not found"),
                    &session,
                    &parsed,
                )
                .map(|_| ())
                .expect_err(name);
            assert_eq!(err.to_string(), want, "{name}");
        }
    }

    #[test]
    fn test_validate_discoverable_login_errors() {
        let w = unvalidated("example.com", &["https://example.com"]);
        let session = SessionData {
            user_id: b"123".to_vec(),
            ..SessionData::default()
        };
        let err = w
            .validate_discoverable_login(
                |_, _| Err::<TestUser, _>("unused"),
                &session,
                &ParsedCredentialAssertionData::default(),
            )
            .expect_err("not discoverable");
        assert_eq!(
            err.to_string(),
            "Session was not initiated as a client-side discoverable login"
        );
    }

    #[test]
    fn test_login_options() {
        let mut have = PublicKeyCredentialRequestOptions::default();
        with_user_verification(UserVerificationRequirement::REQUIRED)(&mut have);
        assert_eq!(
            have,
            PublicKeyCredentialRequestOptions {
                user_verification: UserVerificationRequirement::REQUIRED,
                ..PublicKeyCredentialRequestOptions::default()
            },
            "UserVerification"
        );

        let mut have = PublicKeyCredentialRequestOptions::default();
        with_challenge(b"00000000000000000000000000000000".to_vec())(&mut have);
        assert_eq!(
            have,
            PublicKeyCredentialRequestOptions {
                challenge: UrlEncodedBase64(b"00000000000000000000000000000000".to_vec()),
                ..PublicKeyCredentialRequestOptions::default()
            },
            "Challenge"
        );
    }

    /// The subtests that need no metadata service.
    #[test]
    fn test_validate_login_full() {
        let (parsed, key, challenge, credential_id) = login_none_es256_with_handle();
        let w = unvalidated("example.org", &["https://example.org"]);
        let session = SessionData {
            challenge: challenge.clone(),
            ..SessionData::default()
        };

        let user = user_with(
            TEST_USER_ID,
            vec![credential(&credential_id, &key, UP | BE)],
        );
        let got =
            passkey_login(&w, &user, &session, &parsed).expect("ShouldSucceedNoAllowedCredentials");
        assert_eq!(got.id.0, credential_id);
        assert!(got.flags.user_present);

        let allowed = SessionData {
            allowed_credential_ids: vec![credential_id.clone()],
            ..session.clone()
        };
        let got = passkey_login(&w, &user, &allowed, &parsed)
            .expect("ShouldSucceedWithAllowedCredentials");
        assert_eq!(got.id.0, credential_id);

        let mut wrong_handle = parsed.clone();
        wrong_handle.response.user_handle = b"wrong-user-handle".to_vec();
        let plain = user_with(TEST_USER_ID, vec![credential(&credential_id, &key, 0)]);
        let err = passkey_login(&w, &plain, &session, &wrong_handle)
            .expect_err("ShouldFailUserHandleMismatch");
        assert_eq!(err.to_string(), "User handle and User ID do not match");

        let other = user_with(
            TEST_USER_ID,
            vec![credential(b"different-credential-id", &key, 0)],
        );
        let err =
            passkey_login(&w, &other, &session, &parsed).expect_err("ShouldFailCredentialNotFound");
        assert_eq!(
            err.to_string(),
            "Unable to find the credential for the returned credential ID"
        );

        let not_eligible = user_with(TEST_USER_ID, vec![credential(&credential_id, &key, UP)]);
        let err = passkey_login(&w, &not_eligible, &session, &parsed)
            .expect_err("ShouldFailBackupEligibleFlagMismatch");
        assert_eq!(
            err.to_string(),
            "Backup Eligible flag inconsistency detected during login validation"
        );

        // Go asserts only that this fails.
        let bad_key = user_with(
            TEST_USER_ID,
            vec![credential(&credential_id, b"invalid-public-key", 0)],
        );
        let err =
            passkey_login(&w, &bad_key, &session, &parsed).expect_err("ShouldFailVerifyError");
        assert_eq!(
            err.to_string(),
            "Error parsing the assertion public key: Unsupported Public Key Type"
        );
    }

    #[test]
    fn test_validate_login_rejects_unsolicited_extension_output() {
        let (mut parsed, key, challenge, credential_id) = login_none_es256_with_handle();
        parsed.client_extension_results =
            json::unmarshal::<AuthenticationExtensionsClientOutputs>(br#"{"appid":true}"#).unwrap();
        let w = unvalidated("example.org", &["https://example.org"]);
        let user = user_with(
            TEST_USER_ID,
            vec![credential(&credential_id, &key, UP | BE)],
        );
        let session = SessionData {
            challenge,
            ..SessionData::default()
        };
        let err = passkey_login(&w, &user, &session, &parsed).expect_err("unsolicited appid");
        assert_eq!(
            err.to_string(),
            r#"Error validating the client extension outputs: Client returned the "appid" extension output which was not requested"#
        );
    }

    #[test]
    fn test_validate_login_latches_user_verified() {
        let (parsed, key, challenge, credential_id) = login_none_es256_with_handle();
        let flags = parsed.response.authenticator_data.flags;
        assert!(!flags.has_user_verified());
        assert!(flags.has_backup_state());

        let w = unvalidated("example.org", &["https://example.org"]);
        let user = user_with(
            TEST_USER_ID,
            vec![credential(&credential_id, &key, UP | UV | BE)],
        );
        let session = SessionData {
            challenge,
            ..SessionData::default()
        };
        let got = passkey_login(&w, &user, &session, &parsed).expect("login");
        assert!(got.flags.user_verified);
        assert!(got.flags.protocol_value().has_user_verified());
        assert!(got.flags.backup_state);
    }

    #[test]
    fn test_validate_login_uses_session_relying_party_id() {
        let (parsed, key, challenge, credential_id) = login_none_es256_with_handle();
        let w = unvalidated("example.com", &["https://example.org"]);
        let user = user_with(
            TEST_USER_ID,
            vec![credential(&credential_id, &key, UP | BE)],
        );
        let session = SessionData {
            challenge,
            relying_party_id: "example.org".into(),
            ..SessionData::default()
        };
        let got = passkey_login(&w, &user, &session, &parsed).expect("session RP ID");
        assert_eq!(got.id.0, credential_id);
    }

    #[test]
    fn test_validate_passkey_login_full() {
        let (parsed, key, challenge, credential_id) = login_none_es256_with_handle();
        let w = unvalidated("example.org", &["https://example.org"]);
        let session = SessionData {
            challenge,
            ..SessionData::default()
        };

        let user = user_with(
            TEST_USER_ID,
            vec![credential(&credential_id, &key, UP | BE)],
        );
        let (returned, got) = w
            .validate_passkey_login(|_, _| Ok::<_, String>(user.clone()), &session, &parsed)
            .expect("ShouldSucceed");
        assert_eq!(returned.id, TEST_USER_ID);
        assert_eq!(got.id.0, credential_id);

        // Go asserts only that this fails.
        let other = user_with(TEST_USER_ID, vec![credential(b"different-id", &key, 0)]);
        let err = w
            .validate_passkey_login(|_, _| Ok::<_, String>(other), &session, &parsed)
            .map(|_| ())
            .expect_err("ShouldFailValidateLoginError");
        assert_eq!(
            err.to_string(),
            "Unable to find the credential for the returned credential ID"
        );
    }

    /// Go's `FinishDiscoverableLogin` and `FinishPasskeyLogin` read the body
    /// from an `http.Request`; here it is parsed from bytes and then
    /// validated, as those helpers do.
    #[test]
    fn test_finish_discoverable_and_passkey_login_success() {
        let (vector, key, challenge, credential_id) = spec_vector_none_es256();
        let body = assertion_body(
            &credential_id,
            &vector.raw.assertion_response.authenticator_data.0,
            &vector.raw.assertion_response.client_data_json.0,
            &vector.response.signature,
            Some(TEST_USER_ID),
        );
        let w = unvalidated("example.org", &["https://example.org"]);
        let user = user_with(
            TEST_USER_ID,
            vec![credential(&credential_id, &key, UP | BE)],
        );
        let session = SessionData {
            challenge,
            ..SessionData::default()
        };

        let parsed = parse_credential_request_response_bytes(body.as_bytes()).expect("parse");
        let got = w
            .validate_discoverable_login(|_, _| Ok::<_, String>(&user), &session, &parsed)
            .expect("TestFinishDiscoverableLogin_Success");
        assert_eq!(got.id.0, credential_id);

        let (returned, got) = w
            .validate_passkey_login(|_, _| Ok::<_, String>(&user), &session, &parsed)
            .expect("TestFinishPasskeyLogin_Success");
        assert_eq!(returned.id, TEST_USER_ID);
        assert_eq!(got.id.0, credential_id);
    }

    #[test]
    fn test_begin_login_origin() {
        let w = new(config(
            "example.com",
            "Test",
            &["https://a.example.com", "https://b.example.com"],
        ));
        let cases = [
            ("ShouldNotBindAnOriginWhenTheOptionIsNotSupplied", None, Ok("")),
            ("ShouldBindAConfiguredOrigin", Some("https://b.example.com"), Ok("https://b.example.com")),
            (
                "ShouldRejectAnOriginWhichIsNotConfigured",
                Some("https://c.example.com"),
                Err("error generating assertion: the ceremony origin 'https://c.example.com' must be one of the origins in the 'RPOrigins' configuration"),
            ),
            (
                // Go also configures the origin in RPOpaqueOrigins; the port
                // has none and rejects an opaque origin with the same error.
                "ShouldRejectAnOpaqueOriginEvenWhenItIsConfigured",
                Some("android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"),
                Err("error generating assertion: the ceremony origin 'android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk' can't be bound as it's opaque and an opaque origin is only conveyed in the ceremony response"),
            ),
        ];
        for (name, origin, want) in cases {
            let opts: Vec<_> = origin.map(with_login_origin).into_iter().collect();
            let result = w.begin_discoverable_login(opts);
            match want {
                Ok(origin) => assert_eq!(result.expect(name).1.origin, origin, "{name}"),
                Err(text) => assert_eq!(
                    result.map(|_| ()).expect_err(name).to_string(),
                    text,
                    "{name}"
                ),
            }
        }
    }

    #[test]
    fn test_validate_login_bound_origin() {
        let cases = [
            ("ShouldAcceptTheBoundOrigin", "https://example.org", None),
            (
                "ShouldAcceptAnyConfiguredOriginWhenTheSessionIsNotBound",
                "",
                None,
            ),
            (
                "ShouldRejectAnotherConfiguredOriginWhenTheSessionIsBound",
                "https://other.example.org",
                Some("Error validating origin"),
            ),
        ];
        for (name, session_origin, want) in cases {
            let (parsed, key, challenge, credential_id) = login_none_es256_with_handle();
            let w = unvalidated(
                "example.org",
                &["https://example.org", "https://other.example.org"],
            );
            let user = user_with(
                TEST_USER_ID,
                vec![credential(&credential_id, &key, UP | BE)],
            );
            let session = SessionData {
                challenge,
                origin: session_origin.into(),
                ..SessionData::default()
            };
            let result = passkey_login(&w, &user, &session, &parsed);
            match want {
                None => assert_eq!(result.expect(name).id.0, credential_id, "{name}"),
                Some(text) => assert_eq!(result.expect_err(name).to_string(), text, "{name}"),
            }
        }
    }

    #[test]
    fn test_validate_login_extension_outputs() {
        let cases = [
            (
                "AppIDWithoutSessionValue",
                "fido-u2f",
                "Session Data does not have an appid but Client Output indicates it should be set",
            ),
            (
                "UnsolicitedOutput",
                "packed",
                r#"Error validating the client extension outputs: Client returned the "appid" extension output which was not requested"#,
            ),
        ];
        for (name, attestation_format, want) in cases {
            let (mut parsed, key, challenge, credential_id) = login_none_es256_with_handle();
            parsed.client_extension_results =
                json::unmarshal::<AuthenticationExtensionsClientOutputs>(br#"{"appid":true}"#)
                    .unwrap();
            let w = unvalidated("example.org", &["https://example.org"]);
            let user = user_with(
                TEST_USER_ID,
                vec![Credential {
                    attestation_format: attestation_format.into(),
                    ..credential(&credential_id, &key, UP | BE)
                }],
            );
            let session = SessionData {
                challenge,
                ..SessionData::default()
            };
            let err = passkey_login(&w, &user, &session, &parsed).expect_err(name);
            assert_eq!(err.to_string(), want, "{name}");
        }
    }

    #[test]
    fn test_begin_login_rejects_invalid_config() {
        let w = WebAuthn {
            config: Config::default(),
        };
        let err = w
            .begin_discoverable_login(vec![])
            .map(|_| ())
            .expect_err("empty configuration");
        assert!(
            err.to_string()
                .contains("error occurred validating the configuration"),
            "{err}"
        );
        // As for registration, checked against go-webauthn v0.18.2.
        let w = WebAuthn {
            config: config("example.com", "x", &[]),
        };
        let err = w
            .begin_discoverable_login(vec![])
            .map(|_| ())
            .expect_err("no origins");
        assert_eq!(err.to_string(), "error occurred validating the configuration: must provide at least one value to the 'RPOrigins' field");
    }

    /// The `ValidatePasskeyLogin` subtests.
    #[test]
    fn test_finish_login_failure_session_challenge() {
        let w = WebAuthn {
            config: config("webauthn.io", "test_rp", &["https://webauthn.io"]),
        };
        let mut parsed = ParsedCredentialAssertionData::default();
        parsed.response.user_handle = b"0ToAAAAAAAAAAA".to_vec();
        let cases = [
            (
                "ShouldFailEmpty",
                "",
                "The challenge must be at least 16 bytes but it has a length of 0",
            ),
            (
                "ShouldFailShort",
                "d3JvbmctY2hhbGxlbmdl",
                "The challenge must be at least 16 bytes but it has a length of 15",
            ),
            (
                "ShouldFailInvalid",
                "not base64url!",
                "The challenge could not be decoded: illegal base64 data at input byte 3",
            ),
        ];
        for (name, challenge, info) in cases {
            let session = SessionData {
                challenge: challenge.into(),
                ..SessionData::default()
            };
            let err = w
                .validate_passkey_login(
                    |_, _| -> Result<TestUser, String> {
                        panic!("the handler must not be called for a session with an invalid challenge")
                    },
                    &session,
                    &parsed,
                )
                .map(|_| ())
                .expect_err(name);
            assert_protocol_error(
                &err,
                ErrorType::InvalidRequest,
                "Session has an invalid challenge",
                info,
            );
        }
    }
}
