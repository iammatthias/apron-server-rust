use std::fmt::Write as _;

use super::extensions::{parse_authenticator_extension_outputs, AuthenticatorExtensionOutputs};
use super::Error;
use crate::cbor;

const MIN_AUTH_DATA_LENGTH: usize = 37;
const MIN_ATTESTED_AUTH_LENGTH: usize = 55;
const MAX_CREDENTIAL_ID_LENGTH: usize = 1023;

/// Go's `AuthenticatorFlags` (§6.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthenticatorFlags(pub u8);

impl AuthenticatorFlags {
    pub const USER_PRESENT: u8 = 0x01;
    pub const USER_VERIFIED: u8 = 0x04;
    pub const BACKUP_ELIGIBLE: u8 = 0x08;
    pub const BACKUP_STATE: u8 = 0x10;
    pub const ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
    pub const HAS_EXTENSIONS: u8 = 0x80;

    fn has(self, flag: u8) -> bool {
        self.0 & flag == flag
    }

    pub fn has_user_present(self) -> bool {
        self.has(Self::USER_PRESENT)
    }

    pub fn has_user_verified(self) -> bool {
        self.has(Self::USER_VERIFIED)
    }

    pub fn has_backup_eligible(self) -> bool {
        self.has(Self::BACKUP_ELIGIBLE)
    }

    pub fn has_backup_state(self) -> bool {
        self.has(Self::BACKUP_STATE)
    }

    pub fn has_attested_credential_data(self) -> bool {
        self.has(Self::ATTESTED_CREDENTIAL_DATA)
    }

    pub fn has_extensions(self) -> bool {
        self.has(Self::HAS_EXTENSIONS)
    }
}

/// Go's `AttestedCredentialData` (§6.5.1). The public key is re-encoded as
/// CTAP2 canonical CBOR, as go-webauthn stores it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttestedCredentialData {
    pub aaguid: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub credential_public_key: Vec<u8>,
}

/// Go's `AuthenticatorData` (§6.1).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthenticatorData {
    pub rpid_hash: Vec<u8>,
    pub flags: AuthenticatorFlags,
    pub counter: u32,
    pub att_data: AttestedCredentialData,
    pub ext_data: Vec<u8>,
    pub ext: Option<AuthenticatorExtensionOutputs>,
}

impl AuthenticatorData {
    /// Go's `AuthenticatorData.Unmarshal`.
    pub fn unmarshal(raw: &[u8]) -> Result<AuthenticatorData, Error> {
        if raw.len() < MIN_AUTH_DATA_LENGTH {
            return Err(Error::bad_request()
                .with_details("Authenticator data length too short")
                .with_info(format!(
                    "Expected data greater than {MIN_AUTH_DATA_LENGTH} bytes. Got {} bytes",
                    raw.len()
                )));
        }
        let mut a = AuthenticatorData {
            rpid_hash: raw[..32].to_vec(),
            flags: AuthenticatorFlags(raw[32]),
            counter: u32::from_be_bytes([raw[33], raw[34], raw[35], raw[36]]),
            ..AuthenticatorData::default()
        };
        let mut remaining = raw.len() - MIN_AUTH_DATA_LENGTH;
        if a.flags.has_attested_credential_data() {
            if raw.len() <= MIN_ATTESTED_AUTH_LENGTH {
                return Err(Error::bad_request()
                    .with_details("Attested credential flag set but data is missing"));
            }
            // Go subtracts with an int; this length never exceeds the rest.
            remaining -= a.unmarshal_attested_data(raw)?;
        } else if !a.flags.has_extensions() && raw.len() != MIN_AUTH_DATA_LENGTH {
            return Err(Error::bad_request().with_details("Attested credential flag not set"));
        }
        if a.flags.has_extensions() {
            if remaining == 0 {
                return Err(Error::bad_request()
                    .with_details("Extensions flag set but extensions data is missing"));
            }
            a.ext_data = raw[raw.len() - remaining..].to_vec();
            remaining = 0;
            a.ext = Some(parse_authenticator_extension_outputs(&a.ext_data)?);
        }
        if remaining != 0 {
            return Err(
                Error::bad_request().with_details("Leftover bytes decoding AuthenticatorData")
            );
        }
        Ok(a)
    }

    fn unmarshal_attested_data(&mut self, raw: &[u8]) -> Result<usize, Error> {
        self.att_data.aaguid = raw[37..53].to_vec();
        let id_length = usize::from(u16::from_be_bytes([raw[53], raw[54]]));
        if id_length > MAX_CREDENTIAL_ID_LENGTH {
            return Err(Error::bad_request()
                .with_details("Authenticator attestation data credential id length too long"));
        }
        if raw.len() < 55 + id_length {
            return Err(Error::bad_request()
                .with_details("Authenticator attestation data length too short"));
        }
        self.att_data.credential_id = raw[55..55 + id_length].to_vec();
        let (value, key_length) = cbor::unmarshal_first(&raw[55 + id_length..]).map_err(|err| {
            Error::bad_request()
                .with_details(format!("Could not unmarshal Credential Public Key: {err}"))
        })?;
        self.att_data.credential_public_key = cbor::marshal(&value);
        Ok(16 + 2 + id_length + key_length)
    }

    /// Go's `AuthenticatorData.Verify`: the RP ID hash and the UP and UV
    /// flags (§7.1 steps 13 to 15, §7.2 steps 15 to 17).
    pub fn verify(
        &self,
        rp_id_hash: &[u8],
        app_id_hash: Option<&[u8]>,
        user_verification_required: bool,
        user_presence_required: bool,
    ) -> Result<(), Error> {
        let expected = app_id_hash.unwrap_or(rp_id_hash);
        if self.rpid_hash != expected {
            return Err(Error::verification().with_info(format!(
                "RP Hash mismatch. Expected {} and Received {}",
                hex(expected),
                hex(&self.rpid_hash)
            )));
        }
        if user_presence_required && !self.flags.has_user_present() {
            return Err(Error::verification()
                .with_info("User presence required but flag not set by authenticator"));
        }
        if user_verification_required && !self.flags.has_user_verified() {
            return Err(Error::verification()
                .with_info("User verification required but flag not set by authenticator"));
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
