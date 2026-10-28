use rust_stdlib_crypto::sha256;

use super::webauthncose;
use super::{
    AuthenticatorData, AuthenticatorTransport, CollectedClientData, CredentialParameter, Error,
};
use crate::cbor::{self, Field, FieldKey, FieldKind, Value};

/// Go's `ParsedAttestationResponse`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedAttestationResponse {
    pub collected_client_data: CollectedClientData,
    pub attestation_object: AttestationObject,
    pub transports: Vec<AuthenticatorTransport>,
}

/// Go's `AttestationObject` (§6.5.4).
///
/// Formats: `none`, and `packed` self attestation, are verified as Go does.
/// aprond asks for no attestation, so a conforming client sends one of
/// those. go-webauthn would also verify `packed` with an `x5c` chain, `tpm`,
/// `android-key`, `android-safetynet`, `fido-u2f`, `apple` and `compound`;
/// this port rejects them as unsupported (docs/DEVIATIONS.md).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AttestationObject {
    pub auth_data: AuthenticatorData,
    pub raw_auth_data: Vec<u8>,
    pub format: String,
    /// Go's `map[string]any`; `None` for Go's nil map.
    pub att_statement: Option<Vec<(String, Value)>>,
    /// Go's `Type`, set by verification: `none` or `basic_surrogate`.
    pub kind: String,
}

const ATTESTATION_OBJECT_FIELDS: &[Field] = &[
    Field {
        key: FieldKey::Name("authData"),
        kind: FieldKind::ByteSlice,
    },
    Field {
        key: FieldKey::Name("fmt"),
        kind: FieldKind::String,
    },
    Field {
        key: FieldKey::Name("attStmt"),
        kind: FieldKind::Raw,
    },
];

const NON_COMPOUND_FIELDS: &[Field] = &[
    Field {
        key: FieldKey::Name("fmt"),
        kind: FieldKind::String,
    },
    Field {
        key: FieldKey::Name("attStmt"),
        kind: FieldKind::Raw,
    },
];

impl AttestationObject {
    /// Go's `AttestationObject.UnmarshalCBOR` through `webauthncbor.Unmarshal`.
    pub(crate) fn unmarshal_cbor(data: &[u8]) -> Result<AttestationObject, cbor::Error> {
        let item = cbor::parse(data)?;
        let fields = cbor::decode_struct(
            &item,
            "protocol.attestationObjectEncoded",
            ATTESTATION_OBJECT_FIELDS,
        )?;
        let mut a = AttestationObject {
            raw_auth_data: fields[0].bytes(),
            format: fields[1].string(),
            ..AttestationObject::default()
        };
        let statement = fields[2].raw();
        if statement.is_empty() {
            return Ok(a);
        }
        let item = cbor::parse(statement)?;
        if a.format == "compound" {
            // Go decodes the sub-statements here; this port then rejects the
            // format, but a malformed one still fails parsing as in Go.
            match &item.kind {
                cbor::Kind::Array(items) => {
                    for sub in items {
                        let fields = cbor::decode_struct(
                            sub,
                            "protocol.NonCompoundAttestationObject",
                            NON_COMPOUND_FIELDS,
                        )?;
                        if !fields[1].raw().is_empty() {
                            cbor::decode_string_map(&cbor::parse(fields[1].raw())?)?;
                        }
                    }
                }
                cbor::Kind::Nil => {}
                _ => {
                    return Err(cbor::Error::UnmarshalType {
                        cbor_type: "map",
                        go_type: "[]protocol.NonCompoundAttestationObject",
                        field: None,
                        message: None,
                    })
                }
            }
            return Ok(a);
        }
        a.att_statement = cbor::decode_string_map(&item)?;
        Ok(a)
    }

    fn statement(&self, key: &str) -> Option<&Value> {
        self.att_statement
            .as_ref()?
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    /// Go's `AttestationObject.Verify` (§7.1 steps 12 to 21, without the
    /// metadata service aprond does not configure).
    pub fn verify(
        &mut self,
        relying_party_id: &str,
        client_data_hash: &[u8],
        user_verification_required: bool,
        user_presence_required: bool,
        cred_params: &[CredentialParameter],
    ) -> Result<(), Error> {
        let rp_id_hash = sha256::sum256(relying_party_id.as_bytes());
        self.auth_data.verify(
            &rp_id_hash,
            None,
            user_verification_required,
            user_presence_required,
        )?;
        let pk =
            webauthncose::parse_public_key_data(&self.auth_data.att_data.credential_public_key)
                .map_err(Error::other)?;
        if !cred_params.iter().any(|p| p.algorithm.0 == pk.algorithm) {
            return Err(Error::attestation_format()
                .with_info("Credential public key algorithm not supported"));
        }
        self.verify_attestation(client_data_hash)
    }

    /// Go's `AttestationObject.VerifyAttestation`.
    pub fn verify_attestation(&mut self, client_data_hash: &[u8]) -> Result<(), Error> {
        if self.format == "none" {
            if self.att_statement.as_ref().is_some_and(|s| !s.is_empty()) {
                return Err(Error::attestation_format()
                    .with_info("Attestation format none with attestation present"));
            }
            self.kind = "none".into();
            return Ok(());
        }
        if self.format != "packed" {
            return Err(Error::attestation_format()
                .with_info(format!("Attestation format {} is unsupported", self.format)));
        }
        match self.verify_packed(client_data_hash) {
            Ok(kind) => {
                self.kind = kind.into();
                Ok(())
            }
            Err((kind, err)) => Err(err.with_info(kind)),
        }
    }

    /// Go's `attestationFormatValidationHandlerPacked` (§8.2), for self
    /// attestation. Errors carry the attestation type Go reports with them.
    fn verify_packed(
        &self,
        client_data_hash: &[u8],
    ) -> Result<&'static str, (&'static str, Error)> {
        let Some(alg) = self.statement("alg").and_then(Value::as_go_int64) else {
            return Err((
                "packed",
                Error::attestation_format().with_details("Error retrieving alg value"),
            ));
        };
        let Some(Value::Bytes(sig)) = self.statement("sig") else {
            return Err((
                "packed",
                Error::attestation_format().with_details("Error retrieving sig value"),
            ));
        };
        if let Some(Value::Array(_)) = self.statement("x5c") {
            return Err((
                "",
                Error::attestation_format().with_details(
                    "Basic attestation with an x5c certificate chain is not supported",
                ),
            ));
        }
        if let Some(Value::Bytes(_)) = self.statement("ecdaaKeyId") {
            return Err(("Packed (ECDAA)", Error::not_spec_implemented()));
        }
        let mut data = self.raw_auth_data.clone();
        data.extend_from_slice(client_data_hash);
        let key = webauthncose::parse_public_key(&self.auth_data.att_data.credential_public_key)
            .map_err(|err| {
                (
                    "",
                    Error::attestation_format()
                        .with_details(format!("Error parsing the public key: {err}")),
                )
            })?;
        if key.algorithm() != alg {
            return Err((
                "",
                Error::invalid_attestation()
                    .with_details("Public key algorithm does not equal att statement algorithm"),
            ));
        }
        match webauthncose::verify_signature(&key, &data, sig) {
            Err(err) => Err((
                "",
                Error::attestation_format()
                    .with_details(format!("Error verifying the signature: {err}")),
            )),
            Ok(false) => Err((
                "",
                Error::invalid_attestation().with_details("Unable to verify signature"),
            )),
            Ok(true) => Ok("basic_surrogate"),
        }
    }
}
