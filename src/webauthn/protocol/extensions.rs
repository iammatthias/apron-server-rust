use rust_stdlib::encoding::json::{self, DecodeState, Node};
use rust_stdlib_derive::Deserialize;

use super::{CeremonyType, CredentialProtectionPolicy, Error, UrlEncodedBase64};
use crate::cbor::{self, Value};

/// The client extension outputs go-webauthn models, in the order its
/// `Present` lists them.
const EXTENSION_OUTPUT_NAMES: [&str; 8] = [
    "appid",
    "appidExclude",
    "credProps",
    "prf",
    "largeBlob",
    "remoteClientDataJSON",
    "hmacCreateSecret",
    "hmacGetSecret",
];

/// Go's `AuthenticationExtensionsClientOutputs` (§5.8.1). aprond requests no
/// extension, so only which outputs are present matters: any present output
/// fails the ceremony. The typed members are still decoded, as Go decodes
/// them, so a mistyped output fails parsing instead.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthenticationExtensionsClientOutputs {
    /// Go's `AppID`.
    pub appid: Option<bool>,
    present: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct CredentialPropertiesOutput {
    #[json("rk,omitempty")]
    _rk: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct PrfValues {
    #[json("first")]
    _first: UrlEncodedBase64,
    #[json("second,omitempty")]
    _second: UrlEncodedBase64,
}

#[derive(Debug, Default, Deserialize)]
struct PrfOutputs {
    #[json("enabled,omitempty")]
    _enabled: Option<bool>,
    #[json("results,omitempty")]
    _results: Option<PrfValues>,
}

#[derive(Debug, Default, Deserialize)]
struct LargeBlobOutputs {
    #[json("supported,omitempty")]
    _supported: Option<bool>,
    #[json("blob,omitempty")]
    _blob: UrlEncodedBase64,
    #[json("written,omitempty")]
    _written: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct HmacGetSecretOutputs {
    #[json("output1,omitempty")]
    _output1: UrlEncodedBase64,
    #[json("output2,omitempty")]
    _output2: UrlEncodedBase64,
}

/// Named after Go's local type so decoding errors read as Go's do.
#[allow(non_camel_case_types)]
#[derive(Debug, Default, Deserialize)]
struct alias {
    #[json("appid,omitempty")]
    appid: Option<bool>,
    #[json("appidExclude,omitempty")]
    appid_exclude: Option<bool>,
    #[json("credProps,omitempty")]
    cred_props: Option<CredentialPropertiesOutput>,
    #[json("prf,omitempty")]
    prf: Option<PrfOutputs>,
    #[json("largeBlob,omitempty")]
    large_blob: Option<LargeBlobOutputs>,
    #[json("remoteClientDataJSON,omitempty")]
    remote_client_data_json: Option<bool>,
    #[json("hmacCreateSecret,omitempty")]
    hmac_create_secret: Option<bool>,
    #[json("hmacGetSecret,omitempty")]
    hmac_get_secret: Option<HmacGetSecretOutputs>,
}

impl AuthenticationExtensionsClientOutputs {
    /// Go's `UnmarshalJSON`.
    fn unmarshal(data: &[u8]) -> Result<Self, json::Error> {
        let kind = match data.first() {
            Some(b'n') => return Ok(Self::default()),
            Some(b'{') => None,
            Some(b'[') => Some("array"),
            Some(b'"') => Some("string"),
            Some(b't' | b'f') => Some("bool"),
            _ => Some("number"),
        };
        if let Some(kind) = kind {
            return Err(json::Error::custom(format!(
                "json: cannot unmarshal {kind} into Go value of type protocol.alias"
            )));
        }
        let decoded: alias = json::unmarshal(data)?;
        let json::Value::Object(members) = json::unmarshal::<json::Value>(data)? else {
            unreachable!("checked to be an object above");
        };
        let set = [
            decoded.appid.is_some(),
            decoded.appid_exclude.is_some(),
            decoded.cred_props.is_some(),
            decoded.prf.is_some(),
            decoded.large_blob.is_some(),
            decoded.remote_client_data_json.is_some(),
            decoded.hmac_create_secret.is_some(),
            decoded.hmac_get_secret.is_some(),
        ];
        let mut null_modelled = Vec::new();
        let mut extra = Vec::new();
        for (key, value) in members.iter() {
            match EXTENSION_OUTPUT_NAMES
                .iter()
                .position(|name| name.eq_ignore_ascii_case(key))
            {
                Some(i) if matches!(value, json::Value::Null) => null_modelled.push(i),
                Some(_) => {}
                None => extra.push(key.clone()),
            }
        }
        extra.sort();
        let mut present: Vec<String> = EXTENSION_OUTPUT_NAMES
            .iter()
            .enumerate()
            .filter(|(i, _)| set[*i] || null_modelled.contains(i))
            .map(|(_, name)| (*name).to_owned())
            .collect();
        present.extend(extra);
        Ok(Self {
            appid: decoded.appid,
            present,
        })
    }

    /// Go's `Present`: the names of the outputs the client returned.
    pub fn present(&self) -> &[String] {
        &self.present
    }

    /// Go's `Verify` with no extension requested and the default
    /// `UnsolicitedOutputPolicyReject`.
    pub fn verify(&self, _ceremony: &CeremonyType) -> Result<(), Error> {
        if self.present.is_empty() {
            return Ok(());
        }
        let joined: Vec<String> = self
            .present
            .iter()
            .map(|name| {
                format!("Client returned the {name:?} extension output which was not requested")
            })
            .collect();
        Err(Error::bad_request().with_details(format!(
            "Error validating the client extension outputs: {}",
            joined.join("; ")
        )))
    }
}

impl json::Unmarshaler for AuthenticationExtensionsClientOutputs {
    fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), json::Error> {
        *self = Self::unmarshal(data)?;
        Ok(())
    }
}

impl json::Deserialize for AuthenticationExtensionsClientOutputs {
    fn from_json(value: &json::Value) -> Result<Self, json::Error> {
        Self::unmarshal(value.to_string().as_bytes())
    }

    fn unmarshal_json(node: &Node<'_>, _: &mut DecodeState) -> Result<Self, json::Error> {
        let mut out = Self::default();
        node.unmarshal_into(&mut out)?;
        Ok(out)
    }
    fn json_zero() -> Result<Self, json::Error> {
        Ok(Self::default())
    }
}

/// Go's `AuthenticatorExtensionOutputs`: the authenticator extension outputs
/// (§9) aprond keeps with a credential.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AuthenticatorExtensionOutputs {
    pub cred_protect: Option<CredentialProtectionPolicy>,
    pub min_pin_length: Option<u64>,
    pub cred_blob_set: Option<bool>,
    pub cred_blob: Vec<u8>,
    pub hmac_secret: Option<bool>,
    pub hmac_secret_output: Vec<u8>,
    /// Outputs not modelled, by name.
    pub extra: Vec<(String, Value)>,
}

fn credential_protection_policy(value: &Value) -> Option<CredentialProtectionPolicy> {
    match value.as_go_uint64()? {
        1 => Some(CredentialProtectionPolicy::USER_VERIFICATION_OPTIONAL),
        2 => Some(CredentialProtectionPolicy::USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST),
        3 => Some(CredentialProtectionPolicy::USER_VERIFICATION_REQUIRED),
        _ => None,
    }
}

impl AuthenticatorExtensionOutputs {
    /// Go's `assign`: whether the output was modelled and well typed.
    fn assign(&mut self, key: &str, value: &Value) -> bool {
        match (key, value) {
            ("credentialProtectionPolicy" | "credProtect", _) => {
                match credential_protection_policy(value) {
                    Some(policy) => {
                        self.cred_protect = Some(policy);
                        true
                    }
                    None => false,
                }
            }
            ("minPinLength", Value::Unsigned(n)) => {
                self.min_pin_length = Some(*n);
                true
            }
            ("credBlob", Value::Bool(b)) => {
                self.cred_blob_set = Some(*b);
                true
            }
            ("credBlob", Value::Bytes(b)) => {
                self.cred_blob = b.clone();
                true
            }
            ("hmac-secret", Value::Bool(b)) => {
                self.hmac_secret = Some(*b);
                true
            }
            ("hmac-secret", Value::Bytes(b)) => {
                self.hmac_secret_output = b.clone();
                true
            }
            ("uvm", Value::Array(entries)) => entries.iter().all(|entry| {
                matches!(entry, Value::Array(fields)
                    if fields.len() == 3
                        && fields.iter().all(|f| matches!(f, Value::Unsigned(n) if *n <= u64::from(u32::MAX))))
            }),
            _ => false,
        }
    }
}

/// Go's `ParseAuthenticatorExtensionOutputs`.
pub(super) fn parse_authenticator_extension_outputs(
    data: &[u8],
) -> Result<AuthenticatorExtensionOutputs, Error> {
    let decode_error = |err: cbor::Error| {
        Error::bad_request()
            .with_details("Error decoding authenticator extension outputs")
            .with_info(err.to_string())
    };
    let item = cbor::parse_first(data).map_err(decode_error)?;
    let members = cbor::decode_string_map(&item)
        .map_err(decode_error)?
        .unwrap_or_default();
    if item.raw.len() != data.len() {
        return Err(Error::bad_request()
            .with_details("Leftover bytes decoding authenticator extension outputs")
            .with_info(format!(
                "The extension output map consumed {} of {} bytes",
                item.raw.len(),
                data.len()
            )));
    }
    let mut out = AuthenticatorExtensionOutputs::default();
    let cred_protect = members.iter().any(|(k, _)| k == "credProtect");
    for (key, value) in members {
        if key == "credentialProtectionPolicy" && cred_protect {
            out.extra.push((key, value));
            continue;
        }
        if !out.assign(&key, &value) {
            out.extra.push((key, value));
        }
    }
    Ok(out)
}
