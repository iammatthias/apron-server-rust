use rust_stdlib::time::Time;

use super::protocol::{CredentialParameter, UserVerificationRequirement};

/// Go's `SessionData`: what a ceremony's finish step checks the response
/// against. aprond keeps it in memory only.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct SessionData {
    /// The challenge, unpadded base64url.
    pub challenge: String,
    pub relying_party_id: String,
    /// The single origin the ceremony is bound to, or empty for any
    /// configured origin.
    pub origin: String,
    /// The user handle; empty for a discoverable login.
    pub user_id: Vec<u8>,
    pub allowed_credential_ids: Vec<Vec<u8>>,
    /// When the ceremony expires; the zero time never expires.
    pub expires: Time,
    pub user_verification: UserVerificationRequirement,
    pub cred_params: Vec<CredentialParameter>,
}

impl SessionData {
    /// Go's `GetRelyingPartyID`.
    pub fn get_relying_party_id<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.relying_party_id.is_empty() {
            fallback
        } else {
            &self.relying_party_id
        }
    }

    /// Go's `GetOrigins`.
    pub fn get_origins(&self, fallback: &[String]) -> Vec<String> {
        if self.origin.is_empty() {
            fallback.to_vec()
        } else {
            vec![self.origin.clone()]
        }
    }
}
