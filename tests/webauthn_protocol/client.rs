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
    let ccd =
        setup_collected_client_data(&challenge, "http://example.com", "http://example.com", true);
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
