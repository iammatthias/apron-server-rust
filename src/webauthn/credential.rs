use rust_stdlib::encoding::json::{self, jsontext, v2, Bytes};
use rust_stdlib_derive::{Deserialize, MarshalTo};

use super::protocol::{
    AuthenticatorAttachment, AuthenticatorFlags, AuthenticatorTransport, CredentialDescriptor,
    CredentialProtectionPolicy, CredentialType, ParsedCredentialCreationData, UrlEncodedBase64,
};

/// Go's `webauthn.Credential`: a registered passkey, as aprond stores it.
///
/// It writes the JSON Go's `encoding/json/v2` writes for the Go type (with
/// `[]byte` as standard base64), and reads it with Go's
/// `Credential.UnmarshalJSON`, which uses `encoding/json` v1 rules. Use
/// [`v2::marshal`] and [`v2::unmarshal`] as `persist.go` uses Go's.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, MarshalTo)]
pub struct Credential {
    #[json("id")]
    pub id: Bytes,
    /// The COSE public key, re-encoded as CTAP2 canonical CBOR.
    #[json("publicKey")]
    pub public_key: Bytes,
    #[json("attestationType,omitempty")]
    pub attestation_type: String,
    #[json("attestationFormat,omitempty")]
    pub attestation_format: String,
    #[json("transport,omitempty")]
    pub transport: Vec<AuthenticatorTransport>,
    #[json("flags")]
    pub flags: CredentialFlags,
    #[json("authenticator")]
    pub authenticator: Authenticator,
    #[json("attestation")]
    pub attestation: CredentialAttestation,
    #[json("extensions,omitzero")]
    pub extensions: CredentialExtensions,
}

/// Go's `CredentialFlags`. Go keeps the raw flags byte too, but does not
/// store it, so a credential read back has none.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, MarshalTo)]
pub struct CredentialFlags {
    #[json("userPresent")]
    pub user_present: bool,
    #[json("userVerified")]
    pub user_verified: bool,
    #[json("backupEligible")]
    pub backup_eligible: bool,
    #[json("backupState")]
    pub backup_state: bool,
    #[json(skip)]
    raw: AuthenticatorFlags,
}

/// Go's `webauthn.Authenticator`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, MarshalTo)]
pub struct Authenticator {
    #[json("AAGUID,omitempty")]
    pub aaguid: Bytes,
    #[json("signCount,omitempty")]
    pub sign_count: u32,
    /// Set when an assertion's counter did not advance (§6.1.1); aprond
    /// rejects such a sign-in.
    #[json("cloneWarning,omitempty")]
    pub clone_warning: bool,
    #[json("attachment,omitempty")]
    pub attachment: AuthenticatorAttachment,
}

/// Go's `CredentialAttestation`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, MarshalTo)]
pub struct CredentialAttestation {
    #[json("clientDataJSON,omitempty")]
    pub client_data_json: Bytes,
    #[json("clientDataHash,omitempty")]
    pub client_data_hash: Bytes,
    #[json("authenticatorData,omitempty")]
    pub authenticator_data: Bytes,
    #[json("publicKeyAlgorithm,omitempty")]
    pub public_key_algorithm: i64,
    #[json("object,omitempty")]
    pub object: Bytes,
}

/// Go's `CredentialExtensions`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize, MarshalTo)]
pub struct CredentialExtensions {
    #[json("rk,omitempty")]
    pub rk: Option<bool>,
    #[json("credProtect,omitempty")]
    pub cred_protect: CredentialProtectionPolicy,
    #[json("minPinLength,omitempty")]
    pub min_pin_length: Option<u64>,
    #[json("prfEnabled,omitempty")]
    pub prf_enabled: Option<bool>,
    #[json("largeBlobSupported,omitempty")]
    pub large_blob_supported: Option<bool>,
    #[json("hmacSecret,omitempty")]
    pub hmac_secret: Option<bool>,
    #[json("credBlobSet,omitempty")]
    pub cred_blob_set: Option<bool>,
}

/// Go's `IsAttestationFormatString`.
fn is_attestation_format_string(s: &str) -> bool {
    matches!(
        s,
        "packed"
            | "tpm"
            | "android-key"
            | "android-safetynet"
            | "fido-u2f"
            | "apple"
            | "compound"
            | "none"
    )
}

impl Credential {
    /// Go's `NewCredential`.
    pub fn new(client_data_hash: &[u8], c: &ParsedCredentialCreationData) -> Credential {
        let object = &c.response.attestation_object;
        let raw = &c.raw.attestation_response;
        let mut extensions = CredentialExtensions::default();
        if let Some(ext) = &object.auth_data.ext {
            if let Some(policy) = &ext.cred_protect {
                extensions.cred_protect = policy.clone();
            }
            extensions.min_pin_length = ext.min_pin_length;
            extensions.cred_blob_set = ext.cred_blob_set;
            extensions.hmac_secret = ext.hmac_secret;
        }
        Credential {
            id: Bytes(object.auth_data.att_data.credential_id.clone()),
            public_key: Bytes(object.auth_data.att_data.credential_public_key.clone()),
            attestation_type: object.kind.clone(),
            attestation_format: object.format.clone(),
            transport: c.response.transports.clone(),
            flags: CredentialFlags::new(object.auth_data.flags),
            authenticator: Authenticator {
                aaguid: Bytes(object.auth_data.att_data.aaguid.clone()),
                sign_count: object.auth_data.counter,
                clone_warning: false,
                attachment: c.authenticator_attachment.clone(),
            },
            attestation: CredentialAttestation {
                client_data_json: Bytes(raw.client_data_json.0.clone()),
                client_data_hash: Bytes(client_data_hash.to_vec()),
                authenticator_data: Bytes(raw.authenticator_data.0.clone()),
                public_key_algorithm: raw.public_key_algorithm,
                object: Bytes(raw.attestation_object.0.clone()),
            },
            extensions,
        }
    }

    /// Go's `Credential.Descriptor`.
    pub fn descriptor(&self) -> CredentialDescriptor {
        CredentialDescriptor {
            kind: CredentialType::PUBLIC_KEY,
            credential_id: UrlEncodedBase64(self.id.0.clone()),
            transport: self.transport.clone(),
            attestation_type: self.attestation_type.clone(),
            attestation_format: self.attestation_format.clone(),
        }
    }

    /// Go's `Credential.UnmarshalJSON`: `encoding/json` v1 rules, and a
    /// format string stored as the attestation type by older releases moves
    /// to the attestation format.
    pub fn unmarshal_json(data: &[u8]) -> Result<Credential, json::Error> {
        let mut c: Credential = json::unmarshal(data)?;
        if c.attestation_format.is_empty() && is_attestation_format_string(&c.attestation_type) {
            c.attestation_format = std::mem::take(&mut c.attestation_type);
        }
        Ok(c)
    }
}

impl v2::UnmarshalFrom for Credential {
    fn type_info() -> v2::TypeInfo {
        v2::TypeInfo::of::<Credential>("webauthn.Credential", v2::TypeKind::Struct)
    }

    fn zero() -> Credential {
        Credential::default()
    }

    fn set_zero(&mut self) {
        *self = Credential::default();
    }

    fn unmarshal_default(
        &mut self,
        dec: &mut jsontext::Decoder<'_>,
    ) -> Result<(), jsontext::Error> {
        let value = dec.read_value()?;
        v2::Unmarshaler::unmarshal_json(self, &value.0)
    }

    fn as_unmarshaler(&mut self) -> Option<&mut dyn v2::Unmarshaler> {
        Some(self)
    }
}

impl v2::Unmarshaler for Credential {
    fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), jsontext::Error> {
        *self = Credential::unmarshal_json(data)
            .map_err(|err| jsontext::Error::msg(&err.to_string()))?;
        Ok(())
    }
}

impl CredentialFlags {
    /// Go's `NewCredentialFlags`.
    pub fn new(flags: AuthenticatorFlags) -> CredentialFlags {
        CredentialFlags {
            user_present: flags.has_user_present(),
            user_verified: flags.has_user_verified(),
            backup_eligible: flags.has_backup_eligible(),
            backup_state: flags.has_backup_state(),
            raw: flags,
        }
    }

    /// Go's `CredentialFlags.Update`: the flags of an assertion, except that
    /// user verification never changes from what was recorded.
    pub fn update(&self, flags: AuthenticatorFlags) -> CredentialFlags {
        let mut raw = flags.0;
        if self.user_verified {
            raw |= AuthenticatorFlags::USER_VERIFIED;
        } else {
            raw &= !AuthenticatorFlags::USER_VERIFIED;
        }
        CredentialFlags::new(AuthenticatorFlags(raw))
    }

    /// Go's `ProtocolValue`.
    pub fn protocol_value(&self) -> AuthenticatorFlags {
        self.raw
    }
}

impl Authenticator {
    /// Go's `Authenticator.UpdateCounter` (§6.1.1): a counter that does not
    /// advance, unless both are zero, sets the clone warning and keeps the
    /// stored count.
    pub fn update_counter(&mut self, auth_data_count: u32) {
        if auth_data_count <= self.sign_count && (auth_data_count != 0 || self.sign_count != 0) {
            self.clone_warning = true;
            return;
        }
        self.sign_count = auth_data_count;
    }
}
