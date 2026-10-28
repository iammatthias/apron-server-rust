//! Passkeys: the subset of `github.com/go-webauthn/webauthn` v0.18.2 aprond
//! uses, ported with its verification rules.
//!
//! aprond configures one [`WebAuthn`] from `--webauthn.rp-id` and
//! `--webauthn.origin`, offers discoverable (resident key) credentials with
//! required user verification, and asks for no attestation. Go symbols map to
//! Rust items as follows:
//!
//! | Go | Rust |
//! |---|---|
//! | `webauthn.New(&webauthn.Config{RPID, RPDisplayName, RPOrigins})` | [`WebAuthn::new`] with [`Config`] |
//! | `w.Config.RPID`, `w.Config.RPOrigins` | [`WebAuthn::config`]`.rpid`, `.rp_origins` |
//! | `webauthn.User` (`WebAuthnID`, `WebAuthnName`, `WebAuthnDisplayName`, `WebAuthnCredentials`) | [`User`] (`webauthn_id`, `webauthn_name`, `webauthn_display_name`, `webauthn_credentials`) |
//! | `w.BeginRegistration(user, opts...)` | [`WebAuthn::begin_registration`] |
//! | `webauthn.WithRegistrationOrigin` | [`with_registration_origin`] |
//! | `webauthn.WithResidentKeyRequirement` | [`with_resident_key_requirement`] |
//! | `webauthn.WithAuthenticatorSelection` | [`with_authenticator_selection`] |
//! | `webauthn.WithExclusions` | [`with_exclusions`] |
//! | `w.BeginDiscoverableLogin(opts...)` | [`WebAuthn::begin_discoverable_login`] |
//! | `webauthn.WithLoginOrigin` | [`with_login_origin`] |
//! | `webauthn.WithUserVerification` | [`with_user_verification`] |
//! | `webauthn.WithChallenge` | [`with_challenge`] |
//! | `protocol.ParseCredentialCreationResponseBytes` | [`protocol::parse_credential_creation_response_bytes`] |
//! | `w.CreateCredential(user, session, parsed)` | [`WebAuthn::create_credential`] |
//! | `protocol.ParseCredentialRequestResponseBytes` | [`protocol::parse_credential_request_response_bytes`] |
//! | `w.ValidatePasskeyLogin(handler, session, parsed)` | [`WebAuthn::validate_passkey_login`] |
//! | `w.ValidateDiscoverableLogin` | [`WebAuthn::validate_discoverable_login`] |
//! | `webauthn.SessionData` (`Expires`, ...) | [`SessionData`] (`expires`, ...) |
//! | `webauthn.Credential` (`ID`, `Descriptor()`, `Authenticator.CloneWarning`) | [`Credential`] (`id`, [`Credential::descriptor`], `authenticator.clone_warning`) |
//! | `protocol.CredentialCreation` / `.Response` / `.Response.Timeout` | [`protocol::CredentialCreation`] / `.response` / `.response.timeout` |
//! | `protocol.CredentialAssertion` / `.Response` / `.Response.Timeout` | [`protocol::CredentialAssertion`] / `.response` / `.response.timeout` |
//! | `protocol.CredentialDescriptor` | [`protocol::CredentialDescriptor`] |
//! | `protocol.AuthenticatorSelection{ResidentKey, UserVerification}` | [`protocol::AuthenticatorSelection`] `{resident_key, user_verification, ..}` |
//! | `protocol.ResidentKeyRequirementRequired` | [`protocol::ResidentKeyRequirement::REQUIRED`] |
//! | `protocol.VerificationRequired` | [`protocol::UserVerificationRequirement::REQUIRED`] |
//! | `protocol.IsOriginInHaystack` | [`protocol::is_origin_in_haystack`] |
//! | `*protocol.Error` (`Type`, `Details`, `DevInfo`) | [`protocol::Error`] (`kind`, `details`, `info`) |
//!
//! The option values serialize, through `encoding::json::v2`, to the bytes
//! Go's `encoding/json/v2` writes for them, and [`Credential`] to the JSON
//! `persist.go` stores.

mod credential;
pub mod protocol;
mod session;

use std::fmt;

use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::time;

pub use credential::{
    Authenticator, Credential, CredentialAttestation, CredentialExtensions, CredentialFlags,
};
pub use session::SessionData;

use protocol::webauthncose::CoseAlgorithmIdentifier;
use protocol::{
    AuthenticatorSelection, CredentialAssertion, CredentialCreation, CredentialDescriptor,
    CredentialParameter, CredentialType, Error, ParsedCredentialAssertionData,
    ParsedCredentialCreationData, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RelyingPartyEntity, ResidentKeyRequirement,
    TopOriginVerificationMode, UrlEncodedBase64, UserEntity, UserVerificationRequirement,
};

/// Go's `defaultTimeout`, in milliseconds.
const DEFAULT_TIMEOUT: i64 = 300_000;
/// Go's `defaultTimeoutUVD`: the timeout when user verification is
/// discouraged.
const DEFAULT_TIMEOUT_UVD: i64 = 120_000;

/// Go's `webauthn.Config`, for the fields aprond sets. The others keep Go's
/// defaults: no top origins (verified explicitly), no cross-origin
/// ceremonies, no metadata service or filtering, and unsolicited extension
/// outputs rejected.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Config {
    pub rpid: String,
    pub rp_display_name: String,
    pub rp_origins: Vec<String>,
}

/// Go's `webauthn.WebAuthn`.
#[derive(Clone, Debug)]
pub struct WebAuthn {
    pub config: Config,
}

/// Go's `webauthn.User`: the account a passkey belongs to.
pub trait User {
    /// The user handle: opaque, 1 to 64 bytes.
    fn webauthn_id(&self) -> &[u8];
    fn webauthn_name(&self) -> String;
    fn webauthn_display_name(&self) -> String;
    fn webauthn_credentials(&self) -> &[Credential];
}

impl<T: User + ?Sized> User for &T {
    fn webauthn_id(&self) -> &[u8] {
        (**self).webauthn_id()
    }
    fn webauthn_name(&self) -> String {
        (**self).webauthn_name()
    }
    fn webauthn_display_name(&self) -> String {
        (**self).webauthn_display_name()
    }
    fn webauthn_credentials(&self) -> &[Credential] {
        (**self).webauthn_credentials()
    }
}

/// Go's `RegistrationOption`.
pub type RegistrationOption = Box<dyn FnOnce(&mut PublicKeyCredentialCreationOptions)>;

/// Go's `LoginOption`.
pub type LoginOption = Box<dyn FnOnce(&mut PublicKeyCredentialRequestOptions)>;

/// Go's `WithRegistrationOrigin`: binds the ceremony to one configured
/// origin.
pub fn with_registration_origin(origin: impl Into<String>) -> RegistrationOption {
    let origin = origin.into();
    Box::new(move |o| o.origin = origin)
}

/// Go's `WithResidentKeyRequirement`: sets `residentKey` and the Level 1
/// `requireResidentKey`.
pub fn with_resident_key_requirement(requirement: ResidentKeyRequirement) -> RegistrationOption {
    Box::new(move |o| {
        o.authenticator_selection.require_resident_key =
            Some(requirement == ResidentKeyRequirement::REQUIRED);
        o.authenticator_selection.resident_key = requirement;
    })
}

/// Go's `WithAuthenticatorSelection`: replaces the whole selection, so it
/// drops a `requireResidentKey` an earlier option set, as in Go.
pub fn with_authenticator_selection(selection: AuthenticatorSelection) -> RegistrationOption {
    Box::new(move |o| o.authenticator_selection = selection)
}

/// Go's `WithExclusions`.
pub fn with_exclusions(exclusions: Vec<CredentialDescriptor>) -> RegistrationOption {
    Box::new(move |o| o.credential_exclude_list = exclusions)
}

/// Go's `WithLoginOrigin`: binds the ceremony to one configured origin.
pub fn with_login_origin(origin: impl Into<String>) -> LoginOption {
    let origin = origin.into();
    Box::new(move |o| o.origin = origin)
}

/// Go's `WithUserVerification`.
pub fn with_user_verification(requirement: UserVerificationRequirement) -> LoginOption {
    Box::new(move |o| o.user_verification = requirement)
}

/// Go's `WithChallenge`: replaces the random challenge. It must come from
/// [`protocol::create_challenge`].
pub fn with_challenge(challenge: Vec<u8>) -> LoginOption {
    Box::new(move |o| o.challenge = UrlEncodedBase64(challenge))
}

/// Go's `CredentialParametersDefault`: every algorithm aprond offers, in
/// order of preference.
pub fn credential_parameters_default() -> Vec<CredentialParameter> {
    [
        CoseAlgorithmIdentifier::ES256,
        CoseAlgorithmIdentifier::ES384,
        CoseAlgorithmIdentifier::ES512,
        CoseAlgorithmIdentifier::RS256,
        CoseAlgorithmIdentifier::RS384,
        CoseAlgorithmIdentifier::RS512,
        CoseAlgorithmIdentifier::PS256,
        CoseAlgorithmIdentifier::PS384,
        CoseAlgorithmIdentifier::PS512,
        CoseAlgorithmIdentifier::EDDSA,
    ]
    .into_iter()
    .map(|algorithm| CredentialParameter {
        kind: CredentialType::PUBLIC_KEY,
        algorithm,
    })
    .collect()
}

/// Go's `validateCeremonyOrigin`.
fn validate_ceremony_origin(origin: &str, rp_origins: &[String]) -> Result<(), String> {
    if protocol::is_opaque_origin(origin) {
        return Err(format!("the ceremony origin '{origin}' can't be bound as it's opaque and an opaque origin is only conveyed in the ceremony response"));
    }
    if !protocol::is_origin_in_haystack(origin, rp_origins) {
        return Err(format!(
            "the ceremony origin '{origin}' must be one of the origins in the 'RPOrigins' configuration"
        ));
    }
    Ok(())
}

/// Go's `validateSessionChallenge`.
fn validate_session_challenge(challenge: &str) -> Result<(), Error> {
    let raw = URL_SAFE_NO_PAD.decode(challenge).map_err(|err| {
        Error::bad_request()
            .with_details("Session has an invalid challenge")
            .with_info(format!("The challenge could not be decoded: {err}"))
    })?;
    if raw.len() < protocol::MINIMUM_CHALLENGE_LENGTH {
        return Err(Error::bad_request()
            .with_details("Session has an invalid challenge")
            .with_info(format!(
                "The challenge must be at least {} bytes but it has a length of {}",
                protocol::MINIMUM_CHALLENGE_LENGTH,
                raw.len()
            )));
    }
    Ok(())
}

/// Go's `Config.validate`, with the `errFmtConfigValidate` wrapping both
/// `New` and the Begin functions give its error. Go validates again at each
/// Begin, which matters for a `WebAuthn` built without `New`.
fn validate_config(config: &Config) -> Result<(), String> {
    let invalid = |err: String| format!("error occurred validating the configuration: {err}");
    if !config.rpid.is_empty() {
        protocol::validate_rpid(&config.rpid)
            .map_err(|err| invalid(format!("field 'RPID' is not a valid domain string: {err}")))?;
    }
    if config.rp_origins.is_empty() {
        return Err(invalid(
            "must provide at least one value to the 'RPOrigins' field".into(),
        ));
    }
    Ok(())
}

fn expired(session: &SessionData) -> bool {
    !session.expires.is_zero() && session.expires.before(&time::now())
}

impl WebAuthn {
    /// Go's `webauthn.New`: validates the configuration.
    pub fn new(config: Config) -> Result<WebAuthn, String> {
        validate_config(&config)?;
        Ok(WebAuthn { config })
    }

    /// Go's `BeginRegistration` (§5.4): the creation options for the
    /// browser and the session to finish the ceremony with.
    pub fn begin_registration(
        &self,
        user: &dyn User,
        opts: impl IntoIterator<Item = RegistrationOption>,
    ) -> Result<(CredentialCreation, SessionData), Error> {
        validate_config(&self.config).map_err(Error::other)?;
        let mut response = PublicKeyCredentialCreationOptions {
            relying_party: RelyingPartyEntity {
                name: self.config.rp_display_name.clone(),
                id: self.config.rpid.clone(),
            },
            user: UserEntity {
                name: user.webauthn_name(),
                display_name: user.webauthn_display_name(),
                id: UrlEncodedBase64(user.webauthn_id().to_vec()),
            },
            challenge: protocol::create_challenge(),
            parameters: credential_parameters_default(),
            ..PublicKeyCredentialCreationOptions::default()
        };
        for opt in opts {
            opt(&mut response);
        }
        let fail = |message: String| {
            Error::other(format!("error generating credential creation: {message}"))
        };
        if response.relying_party.id.is_empty() {
            return Err(fail("the relying party id must be provided via the configuration or a functional option for a creation".into()));
        }
        protocol::validate_rpid(&response.relying_party.id).map_err(|err| {
            fail(format!("the relying party id failed to validate as it's not a valid domain string with error: {err}"))
        })?;
        if response.relying_party.name.is_empty() {
            return Err(fail("the relying party display name must be provided via the configuration or a functional option for a creation".into()));
        }
        if !response.origin.is_empty() {
            validate_ceremony_origin(&response.origin, &self.config.rp_origins).map_err(fail)?;
        }
        if response.challenge.0.len() < protocol::MINIMUM_CHALLENGE_LENGTH {
            return Err(fail("the challenge must be at least 16 bytes".into()));
        }
        let handle = response.user.id.0.len();
        if !(protocol::MINIMUM_USER_HANDLE_LENGTH..=protocol::MAXIMUM_USER_HANDLE_LENGTH)
            .contains(&handle)
        {
            return Err(fail(format!(
                "the user id must be between {} and {} bytes but it has a length of {handle}",
                protocol::MINIMUM_USER_HANDLE_LENGTH,
                protocol::MAXIMUM_USER_HANDLE_LENGTH
            )));
        }
        if response.timeout == 0 {
            response.timeout = if response.authenticator_selection.user_verification
                == UserVerificationRequirement::DISCOURAGED
            {
                DEFAULT_TIMEOUT_UVD
            } else {
                DEFAULT_TIMEOUT
            };
        }
        let session = SessionData {
            challenge: response.challenge.encode(),
            relying_party_id: response.relying_party.id.clone(),
            origin: response.origin.clone(),
            user_id: user.webauthn_id().to_vec(),
            user_verification: response.authenticator_selection.user_verification.clone(),
            cred_params: response.parameters.clone(),
            ..SessionData::default()
        };
        Ok((CredentialCreation { response }, session))
    }

    /// Go's `CreateCredential` (§7.1): verifies a parsed registration
    /// response and returns the credential to store.
    pub fn create_credential(
        &self,
        user: &dyn User,
        session: &SessionData,
        mut parsed: ParsedCredentialCreationData,
    ) -> Result<Credential, Error> {
        if user.webauthn_id() != session.user_id.as_slice() {
            return Err(Error::bad_request().with_details("ID mismatch for User and Session"));
        }
        if expired(session) {
            return Err(Error::bad_request().with_details("Session has Expired"));
        }
        validate_session_challenge(&session.challenge)?;
        let client_data_hash = parsed.verify(
            &session.challenge,
            session.get_relying_party_id(&self.config.rpid),
            &session.get_origins(&self.config.rp_origins),
            &[],
            TopOriginVerificationMode::Explicit,
            false,
            session.user_verification == UserVerificationRequirement::REQUIRED,
            true,
            &session.cred_params,
        )?;
        let flags = parsed.response.attestation_object.auth_data.flags;
        if !flags.has_backup_eligible() && flags.has_backup_state() {
            return Err(Error::bad_request().with_details(
                "Backup State Flag is true but Backup Eligible flag is false which is invalid",
            ));
        }
        parsed
            .client_extension_results
            .verify(&protocol::CeremonyType::CREATE)?;
        Ok(Credential::new(&client_data_hash, &parsed))
    }

    /// Go's `BeginDiscoverableLogin` (§5.5): request options with no allowed
    /// credentials, so the authenticator offers its passkeys for the RP.
    pub fn begin_discoverable_login(
        &self,
        opts: impl IntoIterator<Item = LoginOption>,
    ) -> Result<(CredentialAssertion, SessionData), Error> {
        validate_config(&self.config).map_err(Error::other)?;
        let mut response = PublicKeyCredentialRequestOptions {
            relying_party_id: self.config.rpid.clone(),
            ..PublicKeyCredentialRequestOptions::default()
        };
        for opt in opts {
            opt(&mut response);
        }
        if response.challenge.0.is_empty() {
            response.challenge = protocol::create_challenge();
        }
        let fail = |message: String| Error::other(format!("error generating assertion: {message}"));
        if response.challenge.0.len() < protocol::MINIMUM_CHALLENGE_LENGTH {
            return Err(Error::other(
                "error generating assertion: the challenge must be at least 16 bytes",
            ));
        }
        if response.relying_party_id.is_empty() {
            return Err(fail("the relying party id must be provided via the configuration or a functional option for a login".into()));
        }
        protocol::validate_rpid(&response.relying_party_id).map_err(|err| {
            fail(format!("the relying party id failed to validate as it's not a valid domain string with error: {err}"))
        })?;
        if !response.origin.is_empty() {
            validate_ceremony_origin(&response.origin, &self.config.rp_origins).map_err(fail)?;
        }
        if response.timeout == 0 {
            response.timeout =
                if response.user_verification == UserVerificationRequirement::DISCOURAGED {
                    DEFAULT_TIMEOUT_UVD
                } else {
                    DEFAULT_TIMEOUT
                };
        }
        let session = SessionData {
            challenge: response.challenge.encode(),
            relying_party_id: response.relying_party_id.clone(),
            origin: response.origin.clone(),
            allowed_credential_ids: response
                .allowed_credentials
                .iter()
                .map(|c| c.credential_id.0.clone())
                .collect(),
            user_verification: response.user_verification.clone(),
            ..SessionData::default()
        };
        Ok((CredentialAssertion { response }, session))
    }

    /// Go's `ValidateDiscoverableLogin`.
    pub fn validate_discoverable_login<U: User, E: fmt::Display>(
        &self,
        handler: impl FnOnce(&[u8], &[u8]) -> Result<U, E>,
        session: &SessionData,
        parsed: &ParsedCredentialAssertionData,
    ) -> Result<Credential, Error> {
        self.validate_passkey_login(handler, session, parsed)
            .map(|(_, credential)| credential)
    }

    /// Go's `ValidatePasskeyLogin` (§7.2): `handler` finds the user from the
    /// credential ID and user handle; returns that user and the credential
    /// with its counter and flags updated, to store back.
    pub fn validate_passkey_login<U: User, E: fmt::Display>(
        &self,
        handler: impl FnOnce(&[u8], &[u8]) -> Result<U, E>,
        session: &SessionData,
        parsed: &ParsedCredentialAssertionData,
    ) -> Result<(U, Credential), Error> {
        if !session.user_id.is_empty() {
            return Err(Error::bad_request()
                .with_details("Session was not initiated as a client-side discoverable login"));
        }
        if expired(session) {
            return Err(Error::bad_request().with_details("Session has Expired"));
        }
        validate_session_challenge(&session.challenge)?;
        if parsed.response.user_handle.is_empty() {
            return Err(Error::bad_request().with_details(
                "Client-side Discoverable Assertion was attempted with a blank User Handle",
            ));
        }
        let user = handler(&parsed.raw_id, &parsed.response.user_handle).map_err(|err| {
            Error::bad_request().with_details(format!(
                "Failed to lookup Client-side Discoverable Credential: {err}"
            ))
        })?;
        let credential = self.validate_login(&user, session, parsed)?;
        Ok((user, credential))
    }

    /// Go's `validateLogin`.
    fn validate_login(
        &self,
        user: &dyn User,
        session: &SessionData,
        parsed: &ParsedCredentialAssertionData,
    ) -> Result<Credential, Error> {
        let credentials = user.webauthn_credentials();
        if !session.allowed_credential_ids.is_empty() {
            let owned = |id: &[u8]| credentials.iter().any(|c| c.id.0 == id);
            if !session.allowed_credential_ids.iter().all(|id| owned(id)) {
                return Err(Error::bad_request().with_details(
                    "User does not own all credentials from the allowed credential list",
                ));
            }
            if !owned(&parsed.raw_id) {
                return Err(Error::bad_request()
                    .with_details("The credential ID provided is not owned by the user"));
            }
            if !session.allowed_credential_ids.contains(&parsed.raw_id) {
                return Err(Error::bad_request().with_details(
                    "The credential ID provided is not in the sessions allowed credential list",
                ));
            }
        }
        let user_handle = &parsed.response.user_handle;
        if !user_handle.is_empty() && user_handle.as_slice() != user.webauthn_id() {
            return Err(Error::bad_request().with_details("User handle and User ID do not match"));
        }
        let Some(stored) = credentials.iter().find(|c| c.id.0 == parsed.raw_id) else {
            return Err(Error::bad_request()
                .with_details("Unable to find the credential for the returned credential ID"));
        };
        let mut credential = stored.clone();
        // Go's GetAppID: aprond never requests the AppID extension, so a
        // FIDO U2F credential whose client claims it was used fails.
        if parsed.client_extension_results.appid == Some(true)
            && credential.attestation_format == "fido-u2f"
        {
            return Err(Error::bad_request().with_details(
                "Session Data does not have an appid but Client Output indicates it should be set",
            ));
        }
        parsed.verify(
            &session.challenge,
            session.get_relying_party_id(&self.config.rpid),
            &session.get_origins(&self.config.rp_origins),
            &[],
            TopOriginVerificationMode::Explicit,
            false,
            session.user_verification == UserVerificationRequirement::REQUIRED,
            true,
            &credential.public_key.0,
        )?;
        parsed
            .client_extension_results
            .verify(&protocol::CeremonyType::ASSERT)?;
        let flags = parsed.response.authenticator_data.flags;
        if credential.flags.backup_eligible != flags.has_backup_eligible() {
            return Err(Error::bad_request().with_details(
                "Backup Eligible flag inconsistency detected during login validation",
            ));
        }
        if !flags.has_backup_eligible() && flags.has_backup_state() {
            return Err(Error::bad_request().with_details(
                "Backup State Flag is true but Backup Eligible flag is false which is invalid",
            ));
        }
        credential
            .authenticator
            .update_counter(parsed.response.authenticator_data.counter);
        credential.flags = credential.flags.update(flags);
        Ok(credential)
    }
}
