use rust_stdlib_derive::MarshalTo;

use super::webauthncose::CoseAlgorithmIdentifier;
use super::{
    AuthenticatorAttachment, AuthenticatorTransport, ConveyancePreference, CredentialType,
    ResidentKeyRequirement, UrlEncodedBase64, UserVerificationRequirement, CHALLENGE_LENGTH,
};

/// Go's `CredentialCreation`: what `navigator.credentials.create()` takes.
/// aprond sends only [`CredentialCreation::response`].
#[derive(Clone, Debug, Default, PartialEq, MarshalTo)]
pub struct CredentialCreation {
    #[json("publicKey")]
    pub response: PublicKeyCredentialCreationOptions,
}

/// Go's `CredentialAssertion`: what `navigator.credentials.get()` takes.
#[derive(Clone, Debug, Default, PartialEq, MarshalTo)]
pub struct CredentialAssertion {
    #[json("publicKey")]
    pub response: PublicKeyCredentialRequestOptions,
}

/// Go's `PublicKeyCredentialCreationOptions` (§5.4), without the members
/// aprond never sets (`hints`, `attestationFormats`, `extensions`), which Go
/// omits when unset.
#[derive(Clone, Debug, Default, PartialEq, MarshalTo)]
pub struct PublicKeyCredentialCreationOptions {
    #[json("rp")]
    pub relying_party: RelyingPartyEntity,
    #[json("user")]
    pub user: UserEntity,
    #[json("challenge")]
    pub challenge: UrlEncodedBase64,
    #[json("pubKeyCredParams,omitempty")]
    pub parameters: Vec<CredentialParameter>,
    #[json("timeout,omitempty")]
    pub timeout: i64,
    #[json("excludeCredentials,omitempty")]
    pub credential_exclude_list: Vec<CredentialDescriptor>,
    #[json("authenticatorSelection,omitzero")]
    pub authenticator_selection: AuthenticatorSelection,
    #[json("attestation,omitempty")]
    pub attestation: ConveyancePreference,
    /// The single origin the ceremony is bound to; never sent.
    #[json(skip)]
    pub origin: String,
}

/// Go's `PublicKeyCredentialRequestOptions` (§5.5), without the members
/// aprond never sets (`hints`, `extensions`).
#[derive(Clone, Debug, Default, PartialEq, MarshalTo)]
pub struct PublicKeyCredentialRequestOptions {
    #[json("challenge")]
    pub challenge: UrlEncodedBase64,
    #[json("timeout,omitempty")]
    pub timeout: i64,
    #[json("rpId,omitempty")]
    pub relying_party_id: String,
    #[json("allowCredentials,omitempty")]
    pub allowed_credentials: Vec<CredentialDescriptor>,
    #[json("userVerification,omitempty")]
    pub user_verification: UserVerificationRequirement,
    /// The single origin the ceremony is bound to; never sent.
    #[json(skip)]
    pub origin: String,
}

/// Go's `RelyingPartyEntity`, with its embedded `CredentialEntity` name.
#[derive(Clone, Debug, Default, PartialEq, MarshalTo)]
pub struct RelyingPartyEntity {
    #[json("name")]
    pub name: String,
    #[json("id")]
    pub id: String,
}

/// Go's `UserEntity`, with its embedded `CredentialEntity` name. Go's `ID`
/// is an `any`; aprond always sends the user handle as base64url.
#[derive(Clone, Debug, Default, PartialEq, MarshalTo)]
pub struct UserEntity {
    #[json("name")]
    pub name: String,
    #[json("displayName")]
    pub display_name: String,
    #[json("id")]
    pub id: UrlEncodedBase64,
}

/// Go's `CredentialParameter`.
#[derive(Clone, Debug, Default, PartialEq, MarshalTo)]
pub struct CredentialParameter {
    #[json("type")]
    pub kind: CredentialType,
    #[json("alg")]
    pub algorithm: CoseAlgorithmIdentifier,
}

/// Go's `CredentialDescriptor` (§5.10.3).
#[derive(Clone, Debug, Default, PartialEq, MarshalTo)]
pub struct CredentialDescriptor {
    #[json("type")]
    pub kind: CredentialType,
    #[json("id")]
    pub credential_id: UrlEncodedBase64,
    #[json("transports,omitempty")]
    pub transport: Vec<AuthenticatorTransport>,
    #[json(skip)]
    pub attestation_type: String,
    #[json(skip)]
    pub attestation_format: String,
}

/// Go's `AuthenticatorSelection` (§5.4.4).
#[derive(Clone, Debug, Default, PartialEq, MarshalTo)]
pub struct AuthenticatorSelection {
    #[json("authenticatorAttachment,omitempty")]
    pub authenticator_attachment: AuthenticatorAttachment,
    #[json("requireResidentKey,omitempty")]
    pub require_resident_key: Option<bool>,
    #[json("residentKey,omitempty")]
    pub resident_key: ResidentKeyRequirement,
    #[json("userVerification,omitempty")]
    pub user_verification: UserVerificationRequirement,
}

/// Go's `CreateChallenge`: [`CHALLENGE_LENGTH`] random bytes.
pub fn create_challenge() -> UrlEncodedBase64 {
    let mut challenge = vec![0u8; CHALLENGE_LENGTH];
    rust_stdlib_crypto::rand::read(&mut challenge);
    UrlEncodedBase64(challenge)
}
