//! login_test.go of go-webauthn's `webauthn` package. mod.rs lists the
//! cases the port leaves out.

use super::*;

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
    let got =
        passkey_login(&w, &user, &allowed, &parsed).expect("ShouldSucceedWithAllowedCredentials");
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
    let err = passkey_login(&w, &bad_key, &session, &parsed).expect_err("ShouldFailVerifyError");
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
            json::unmarshal::<AuthenticationExtensionsClientOutputs>(br#"{"appid":true}"#).unwrap();
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
