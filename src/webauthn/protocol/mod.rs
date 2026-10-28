//! go-webauthn's `protocol` package, for the subset aprond uses: the option
//! types sent to browsers, parsing and verifying registration and assertion
//! responses, and origin matching.

use std::borrow::Cow;
use std::fmt;

use rust_stdlib::encoding::json::{self, jsontext, v2, DecodeState, Node};

mod assertion;
mod attestation;
mod authenticator;
mod base64;
mod client;
mod credential;
mod error;
mod extensions;
mod options;
mod utils;
pub mod webauthncose;

pub use assertion::{
    parse_credential_request_response_bytes, ParsedAssertionResponse, ParsedCredentialAssertionData,
};
pub use attestation::{AttestationObject, ParsedAttestationResponse};
pub use authenticator::{AttestedCredentialData, AuthenticatorData, AuthenticatorFlags};
pub use base64::UrlEncodedBase64;
pub use client::{is_origin_in_haystack, CollectedClientData, TokenBinding};
pub use credential::{parse_credential_creation_response_bytes, ParsedCredentialCreationData};
pub use error::{Error, ErrorType};
pub use extensions::{AuthenticationExtensionsClientOutputs, AuthenticatorExtensionOutputs};
pub use options::{
    create_challenge, AuthenticatorSelection, CredentialAssertion, CredentialCreation,
    CredentialDescriptor, CredentialParameter, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions, RelyingPartyEntity, UserEntity,
};
pub use utils::{is_opaque_origin, validate_rpid};

/// Go's `MinimumChallengeLength`.
pub const MINIMUM_CHALLENGE_LENGTH: usize = 16;
/// Go's `ChallengeLength`: the bytes in a generated challenge.
pub const CHALLENGE_LENGTH: usize = 32;
/// Go's `MinimumUserHandleLength`.
pub const MINIMUM_USER_HANDLE_LENGTH: usize = 1;
/// Go's `MaximumUserHandleLength`.
pub const MAXIMUM_USER_HANDLE_LENGTH: usize = 64;

/// Declares a Go string type with named constants. Unknown values are kept,
/// as Go's string types keep them, and the type writes and reads itself as a
/// JSON string through both `encoding/json` and `encoding/json/v2`.
macro_rules! string_type {
    (
        $(#[$doc:meta])*
        $name:ident = $go:literal {
            $($(#[$cdoc:meta])* $konst:ident = $value:literal,)*
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name(pub Cow<'static, str>);

        impl $name {
            $($(#[$cdoc])* pub const $konst: $name = $name(Cow::Borrowed($value));)*

            pub fn new(value: impl Into<String>) -> $name {
                $name(Cow::Owned(value.into()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn is_empty(&self) -> bool {
                self.0.is_empty()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl json::Serialize for $name {
            fn to_json(&self) -> Result<json::Value, json::Error> {
                self.as_str().to_json()
            }
            fn serialize(&self, s: &mut json::Serializer) -> Result<(), json::Error> {
                self.as_str().serialize(s)
            }
            fn is_empty_value(&self) -> bool {
                self.is_empty()
            }
            fn is_zero_value(&self) -> bool {
                self.is_empty()
            }
        }

        impl json::Deserialize for $name {
            fn from_json(value: &json::Value) -> Result<$name, json::Error> {
                String::from_json(value).map($name::new)
            }
            fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<$name, json::Error> {
                String::unmarshal_json(node, cx).map($name::new)
            }
            fn json_zero() -> Result<$name, json::Error> {
                Ok($name::default())
            }
        }

        impl v2::MarshalTo for $name {
            fn type_info() -> v2::TypeInfo {
                v2::TypeInfo::of::<$name>($go, v2::TypeKind::String)
            }
            fn marshal_default(&self, enc: &mut jsontext::Encoder<'_>) -> Result<(), jsontext::Error> {
                self.as_str().to_owned().marshal_default(enc)
            }
            fn is_zero_value(&self) -> bool {
                self.is_empty()
            }
            fn is_empty_value(&self) -> Option<bool> {
                Some(self.is_empty())
            }
        }
    };
}

string_type! {
    /// Go's `CredentialType`.
    CredentialType = "protocol.CredentialType" {
        /// Go's `PublicKeyCredentialType`.
        PUBLIC_KEY = "public-key",
    }
}

string_type! {
    /// Go's `UserVerificationRequirement`.
    UserVerificationRequirement = "protocol.UserVerificationRequirement" {
        /// Go's `VerificationRequired`.
        REQUIRED = "required",
        /// Go's `VerificationPreferred`.
        PREFERRED = "preferred",
        /// Go's `VerificationDiscouraged`.
        DISCOURAGED = "discouraged",
    }
}

string_type! {
    /// Go's `ResidentKeyRequirement`.
    ResidentKeyRequirement = "protocol.ResidentKeyRequirement" {
        /// Go's `ResidentKeyRequirementDiscouraged`.
        DISCOURAGED = "discouraged",
        /// Go's `ResidentKeyRequirementPreferred`.
        PREFERRED = "preferred",
        /// Go's `ResidentKeyRequirementRequired`.
        REQUIRED = "required",
    }
}

string_type! {
    /// Go's `AuthenticatorAttachment`.
    AuthenticatorAttachment = "protocol.AuthenticatorAttachment" {
        /// Go's `Platform`.
        PLATFORM = "platform",
        /// Go's `CrossPlatform`.
        CROSS_PLATFORM = "cross-platform",
    }
}

string_type! {
    /// Go's `AuthenticatorTransport`.
    AuthenticatorTransport = "protocol.AuthenticatorTransport" {
        USB = "usb",
        NFC = "nfc",
        BLE = "ble",
        SMART_CARD = "smart-card",
        HYBRID = "hybrid",
        INTERNAL = "internal",
    }
}

string_type! {
    /// Go's `ConveyancePreference`. aprond leaves it unset, so the creation
    /// options omit `attestation`.
    ConveyancePreference = "protocol.ConveyancePreference" {
        /// Go's `PreferNoAttestation`.
        NONE = "none",
        /// Go's `PreferIndirectAttestation`.
        INDIRECT = "indirect",
        /// Go's `PreferDirectAttestation`.
        DIRECT = "direct",
        /// Go's `PreferEnterpriseAttestation`.
        ENTERPRISE = "enterprise",
    }
}

string_type! {
    /// Go's `CeremonyType`.
    CeremonyType = "protocol.CeremonyType" {
        /// Go's `CreateCeremony`.
        CREATE = "webauthn.create",
        /// Go's `AssertCeremony`.
        ASSERT = "webauthn.get",
    }
}

string_type! {
    /// Go's `CredentialProtectionPolicy`.
    CredentialProtectionPolicy = "protocol.CredentialProtectionPolicy" {
        USER_VERIFICATION_OPTIONAL = "userVerificationOptional",
        USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST = "userVerificationOptionalWithCredentialIDList",
        USER_VERIFICATION_REQUIRED = "userVerificationRequired",
    }
}

/// Go's `TopOriginVerificationMode`. `webauthn.New` turns the default into
/// `Explicit`, which aprond keeps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TopOriginVerificationMode {
    #[default]
    Default,
    Auto,
    Implicit,
    Explicit,
}
