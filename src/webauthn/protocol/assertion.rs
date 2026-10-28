use rust_stdlib::encoding::base64::URL_SAFE_NO_PAD;
use rust_stdlib::encoding::json;
use rust_stdlib_crypto::sha256;
use rust_stdlib_derive::Deserialize;

use super::credential::decode_bytes;
use super::webauthncose;
use super::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAttachment, AuthenticatorData,
    CeremonyType, CollectedClientData, Error, TopOriginVerificationMode, UrlEncodedBase64,
};

/// Go's `CredentialAssertionResponse`, with its embedded
/// `PublicKeyCredential` and `Credential` members inlined.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct CredentialAssertionResponse {
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
    pub assertion_response: AuthenticatorAssertionResponse,
}

/// Go's `AuthenticatorAssertionResponse` (§5.2.2).
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct AuthenticatorAssertionResponse {
    #[json("clientDataJSON")]
    pub client_data_json: UrlEncodedBase64,
    #[json("authenticatorData")]
    pub authenticator_data: UrlEncodedBase64,
    #[json("signature")]
    pub signature: UrlEncodedBase64,
    #[json("userHandle,omitempty")]
    pub user_handle: UrlEncodedBase64,
}

/// Go's `ParsedAssertionResponse`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedAssertionResponse {
    pub collected_client_data: CollectedClientData,
    pub authenticator_data: AuthenticatorData,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// Go's `ParsedCredentialAssertionData`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParsedCredentialAssertionData {
    pub id: String,
    pub kind: String,
    pub raw_id: Vec<u8>,
    pub client_extension_results: AuthenticationExtensionsClientOutputs,
    pub authenticator_attachment: AuthenticatorAttachment,
    pub response: ParsedAssertionResponse,
    pub raw: CredentialAssertionResponse,
}

/// Go's `ParseCredentialRequestResponseBytes`: parses an authentication
/// response, the `PublicKeyCredential` JSON a browser returns.
pub fn parse_credential_request_response_bytes(
    data: &[u8],
) -> Result<ParsedCredentialAssertionData, Error> {
    let car: CredentialAssertionResponse = decode_bytes(data).map_err(|err| {
        Error::bad_request()
            .with_details("Parse error for Assertion")
            .with_info(err.to_string())
    })?;
    if car.id.is_empty() {
        return Err(
            Error::bad_request().with_details("CredentialAssertionResponse with ID missing")
        );
    }
    let raw_id = URL_SAFE_NO_PAD.decode(&car.id).map_err(|_| {
        Error::bad_request()
            .with_details("CredentialAssertionResponse with ID not base64url encoded")
    })?;
    if raw_id.is_empty() {
        return Err(Error::bad_request()
            .with_details("CredentialAssertionResponse with ID that decodes to no bytes"));
    }
    if car.kind != "public-key" {
        return Err(Error::bad_request().with_details("CredentialAssertionResponse with bad type"));
    }
    if raw_id != car.raw_id.0 {
        return Err(Error::bad_request()
            .with_details("CredentialAssertionResponse with ID that does not match the rawId"));
    }
    let authenticator_attachment = match car.authenticator_attachment.as_str() {
        "platform" => AuthenticatorAttachment::PLATFORM,
        "cross-platform" => AuthenticatorAttachment::CROSS_PLATFORM,
        _ => AuthenticatorAttachment::default(),
    };
    // Go returns this JSON error as is.
    let collected_client_data: CollectedClientData =
        json::unmarshal(&car.assertion_response.client_data_json.0).map_err(Error::other)?;
    let authenticator_data =
        AuthenticatorData::unmarshal(&car.assertion_response.authenticator_data.0)
            .map_err(|_| Error::parsing_data().with_details("Error unmarshalling auth data"))?;
    Ok(ParsedCredentialAssertionData {
        id: car.id.clone(),
        kind: car.kind.clone(),
        raw_id: car.raw_id.0.clone(),
        client_extension_results: car.client_extension_results.clone(),
        authenticator_attachment,
        response: ParsedAssertionResponse {
            collected_client_data,
            authenticator_data,
            signature: car.assertion_response.signature.0.clone(),
            user_handle: car.assertion_response.user_handle.0.clone(),
        },
        raw: car,
    })
}

impl ParsedCredentialAssertionData {
    /// Go's `ParsedCredentialAssertionData.Verify` (§7.2 steps 8 to 21),
    /// without the FIDO AppID extension, which aprond never requests.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        stored_challenge: &str,
        relying_party_id: &str,
        rp_origins: &[String],
        rp_top_origins: &[String],
        rp_top_origins_verify: TopOriginVerificationMode,
        allow_cross_origin: bool,
        verify_user: bool,
        verify_user_presence: bool,
        credential_bytes: &[u8],
    ) -> Result<(), Error> {
        self.response.collected_client_data.verify(
            stored_challenge,
            &CeremonyType::ASSERT,
            rp_origins,
            rp_top_origins,
            rp_top_origins_verify,
            allow_cross_origin,
        )?;
        let rp_id_hash = sha256::sum256(relying_party_id.as_bytes());
        self.response.authenticator_data.verify(
            &rp_id_hash,
            None,
            verify_user,
            verify_user_presence,
        )?;
        let client_data_hash = sha256::sum256(&self.raw.assertion_response.client_data_json.0);
        let mut sig_data = self.raw.assertion_response.authenticator_data.0.clone();
        sig_data.extend_from_slice(&client_data_hash);
        let key = webauthncose::parse_public_key(credential_bytes).map_err(|err| {
            Error::assertion_signature()
                .with_details(format!("Error parsing the assertion public key: {err}"))
        })?;
        match webauthncose::verify_signature(&key, &sig_data, &self.response.signature) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::assertion_signature()
                .with_details("Error validating the assertion signature: <nil>")),
            Err(err) => Err(Error::assertion_signature()
                .with_details(format!("Error validating the assertion signature: {err}"))),
        }
    }
}
