use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::encoding::json::{self, Deserialize};
use rust_stdlib_crypto::sha256;
use rust_stdlib_derive::Deserialize;

use super::attestation::{AttestationObject, ParsedAttestationResponse};
use super::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAttachment, AuthenticatorData,
    AuthenticatorTransport, CeremonyType, CollectedClientData, CredentialParameter, Error,
    TopOriginVerificationMode, UrlEncodedBase64,
};

/// Go's `decodeBytes`: one JSON value, then only whitespace.
pub(super) fn decode_bytes<T: Deserialize>(data: &[u8]) -> Result<T, json::Error> {
    let mut decoder = json::Decoder::new(data);
    let value = decoder.decode::<T>()?;
    match decoder.token() {
        Err(json::Error::Eof) => Ok(value),
        _ => Err(json::Error::custom("body contains trailing data")),
    }
}

/// Go's `CredentialCreationResponse`, with its embedded
/// `PublicKeyCredential` and `Credential` members inlined.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct CredentialCreationResponse {
    #[json("id")]
    pub id: String,
    #[json("type")]
    pub kind: String,
    #[json("rawId")]
    pub raw_id: UrlEncodedBase64,
    #[json("clientExtensionResults,omitzero")]
    pub client_extension_results: AuthenticationExtensionsClientOutputs,
    #[json("authenticatorAttachment,omitempty")]
    pub authenticator_attachment: String,
    #[json("response")]
    pub attestation_response: AuthenticatorAttestationResponse,
}

/// Go's `AuthenticatorAttestationResponse` (§5.2.1), with its embedded
/// `AuthenticatorResponse` inlined.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct AuthenticatorAttestationResponse {
    #[json("clientDataJSON")]
    pub client_data_json: UrlEncodedBase64,
    #[json("transports,omitempty")]
    pub transports: Vec<String>,
    #[json("authenticatorData")]
    pub authenticator_data: UrlEncodedBase64,
    #[json("publicKey")]
    pub public_key: UrlEncodedBase64,
    #[json("publicKeyAlgorithm")]
    pub public_key_algorithm: i64,
    #[json("attestationObject")]
    pub attestation_object: UrlEncodedBase64,
}

impl AuthenticatorAttestationResponse {
    /// Go's `AuthenticatorAttestationResponse.Parse`.
    fn parse(&self) -> Result<ParsedAttestationResponse, Error> {
        let collected_client_data: CollectedClientData = json::unmarshal(&self.client_data_json.0)
            .map_err(|err| Error::parsing_data().with_info(err.to_string()))?;
        let mut attestation_object = AttestationObject::unmarshal_cbor(&self.attestation_object.0)
            .map_err(|err| Error::parsing_data().with_info(err.to_string()))?;
        attestation_object.auth_data =
            AuthenticatorData::unmarshal(&attestation_object.raw_auth_data)?;
        if !attestation_object
            .auth_data
            .flags
            .has_attested_credential_data()
        {
            return Err(Error::attestation_format()
                .with_info("Attestation missing attested credential data flag"));
        }
        let transports = self
            .transports
            .iter()
            .map(|t| match t.as_str() {
                "cable" => AuthenticatorTransport::HYBRID,
                other => AuthenticatorTransport::new(other),
            })
            .collect();
        Ok(ParsedAttestationResponse {
            collected_client_data,
            attestation_object,
            transports,
        })
    }
}

/// Go's `ParsedCredentialCreationData`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedCredentialCreationData {
    pub id: String,
    pub kind: String,
    pub raw_id: Vec<u8>,
    pub client_extension_results: AuthenticationExtensionsClientOutputs,
    pub authenticator_attachment: AuthenticatorAttachment,
    pub response: ParsedAttestationResponse,
    pub raw: CredentialCreationResponse,
}

/// Go's `ParseCredentialCreationResponseBytes`: parses a registration
/// response, the `PublicKeyCredential` JSON a browser returns.
pub fn parse_credential_creation_response_bytes(
    data: &[u8],
) -> Result<ParsedCredentialCreationData, Error> {
    let ccr: CredentialCreationResponse = decode_bytes(data).map_err(|err| {
        Error::bad_request()
            .with_details("Parse error for Registration")
            .with_info(err.to_string())
    })?;
    let parse_error = |info: &str| {
        Error::bad_request()
            .with_details("Parse error for Registration")
            .with_info(info)
    };
    if ccr.id.is_empty() {
        return Err(parse_error("Missing ID"));
    }
    let id = match URL_SAFE_NO_PAD.decode(&ccr.id) {
        Ok(id) if !id.is_empty() => id,
        _ => return Err(parse_error("ID not base64.RawURLEncoded")),
    };
    if ccr.kind.is_empty() {
        return Err(parse_error("Missing type"));
    }
    if ccr.kind != "public-key" {
        return Err(parse_error("Type not public-key"));
    }
    if id != ccr.raw_id.0 {
        return Err(parse_error("ID does not match rawId"));
    }
    let response = ccr
        .attestation_response
        .parse()
        .map_err(|_| Error::parsing_data().with_details("Error parsing attestation response"))?;
    let authenticator_attachment = match ccr.authenticator_attachment.as_str() {
        "platform" => AuthenticatorAttachment::PLATFORM,
        "cross-platform" => AuthenticatorAttachment::CROSS_PLATFORM,
        _ => AuthenticatorAttachment::default(),
    };
    Ok(ParsedCredentialCreationData {
        id: ccr.id.clone(),
        kind: ccr.kind.clone(),
        raw_id: ccr.raw_id.0.clone(),
        client_extension_results: ccr.client_extension_results.clone(),
        authenticator_attachment,
        response,
        raw: ccr,
    })
}

impl ParsedCredentialCreationData {
    /// Go's `ParsedCredentialCreationData.Verify` (§7.1 steps 7 to 21):
    /// returns the client data hash.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &mut self,
        stored_challenge: &str,
        relying_party_id: &str,
        rp_origins: &[String],
        rp_top_origins: &[String],
        rp_top_origins_verify: TopOriginVerificationMode,
        allow_cross_origin: bool,
        verify_user: bool,
        verify_user_presence: bool,
        cred_params: &[CredentialParameter],
    ) -> Result<Vec<u8>, Error> {
        self.response.collected_client_data.verify(
            stored_challenge,
            &CeremonyType::CREATE,
            rp_origins,
            rp_top_origins,
            rp_top_origins_verify,
            allow_cross_origin,
        )?;
        let client_data_hash =
            sha256::sum256(&self.raw.attestation_response.client_data_json.0).to_vec();
        self.response.attestation_object.verify(
            relying_party_id,
            &client_data_hash,
            verify_user,
            verify_user_presence,
            cred_params,
        )?;
        if self.raw_id
            != self
                .response
                .attestation_object
                .auth_data
                .att_data
                .credential_id
        {
            return Err(Error::verification()
                .with_details("Error validating the attested credential id")
                .with_info("The credential id reported by the client does not match the credential id in the attested credential data"));
        }
        Ok(client_data_hash)
    }
}
