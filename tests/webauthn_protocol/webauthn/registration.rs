//! registration_test.go of go-webauthn's `webauthn` package. mod.rs lists
//! the cases the port leaves out.

use super::*;

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
        Box::new(move |o: &mut PublicKeyCredentialCreationOptions| o.user.id = UrlEncodedBase64(id))
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
        let result = w.create_credential(&user(TEST_USER_ID), &session, parse_registration(&body));
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
