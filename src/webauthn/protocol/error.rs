use std::fmt;

/// Go's `protocol.Error` `Type`. [`ErrorType::Other`] stands for an error
/// that is not a `*protocol.Error` in Go, such as a JSON or CBOR decoding
/// error go-webauthn returns as is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorType {
    InvalidRequest,
    PolicyRestriction,
    ChallengeMismatch,
    ParseError,
    AuthData,
    VerificationError,
    AttestationError,
    InvalidAttestation,
    InvalidCertificate,
    InvalidSignature,
    InvalidKeyType,
    UnsupportedKeyAlgorithm,
    SpecUnimplemented,
    NotImplemented,
    Other,
}

impl ErrorType {
    /// The Go `Type` string; empty for [`ErrorType::Other`].
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorType::InvalidRequest => "invalid_request",
            ErrorType::PolicyRestriction => "policy_restriction",
            ErrorType::ChallengeMismatch => "challenge_mismatch",
            ErrorType::ParseError => "parse_error",
            ErrorType::AuthData => "auth_data",
            ErrorType::VerificationError => "verification_error",
            ErrorType::AttestationError => "attestation_error",
            ErrorType::InvalidAttestation => "invalid_attestation",
            ErrorType::InvalidCertificate => "invalid_certificate",
            ErrorType::InvalidSignature => "invalid_signature",
            ErrorType::InvalidKeyType => "invalid_key_type",
            ErrorType::UnsupportedKeyAlgorithm => "unsupported_key_algorithm",
            ErrorType::SpecUnimplemented => "spec_unimplemented",
            ErrorType::NotImplemented => "not_implemented",
            ErrorType::Other => "",
        }
    }
}

/// Go's `protocol.Error`, or any other error go-webauthn returns. Its
/// `Display` is Go's `Error()`: the details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorType,
    pub details: String,
    /// Go's `DevInfo`.
    pub info: String,
}

impl Error {
    fn base(kind: ErrorType, details: &str) -> Error {
        Error {
            kind,
            details: details.to_owned(),
            info: String::new(),
        }
    }

    /// An error that is not a `*protocol.Error` in Go: its text is all Go
    /// keeps.
    pub fn other(message: impl fmt::Display) -> Error {
        Error::base(ErrorType::Other, &message.to_string())
    }

    /// Go's `WithDetails`.
    pub fn with_details(mut self, details: impl Into<String>) -> Error {
        self.details = details.into();
        self
    }

    /// Go's `WithInfo`.
    pub fn with_info(mut self, info: impl Into<String>) -> Error {
        self.info = info.into();
        self
    }

    /// Go's `ErrBadRequest`.
    pub fn bad_request() -> Error {
        Error::base(ErrorType::InvalidRequest, "Error reading the request data")
    }

    /// Go's `ErrPolicyRestriction`.
    pub fn policy_restriction() -> Error {
        Error::base(
            ErrorType::PolicyRestriction,
            "Policy restriction prevented the operation from completing",
        )
    }

    /// Go's `ErrParsingData`.
    pub fn parsing_data() -> Error {
        Error::base(
            ErrorType::ParseError,
            "Error parsing the authenticator response",
        )
    }

    /// Go's `ErrVerification`.
    pub fn verification() -> Error {
        Error::base(
            ErrorType::VerificationError,
            "Error validating the authenticator response",
        )
    }

    /// Go's `ErrAttestation`.
    pub fn attestation() -> Error {
        Error::base(
            ErrorType::AttestationError,
            "Error validating the attestation data provided",
        )
    }

    /// Go's `ErrInvalidAttestation`.
    pub fn invalid_attestation() -> Error {
        Error::base(ErrorType::InvalidAttestation, "Invalid attestation data")
    }

    /// Go's `ErrAttestationFormat`.
    pub fn attestation_format() -> Error {
        Error::base(ErrorType::InvalidAttestation, "Invalid attestation format")
    }

    /// Go's `ErrAssertionSignature`.
    pub fn assertion_signature() -> Error {
        Error::base(
            ErrorType::InvalidSignature,
            "Assertion Signature against auth data and client hash is not valid",
        )
    }

    /// Go's `ErrUnsupportedKey`.
    pub fn unsupported_key() -> Error {
        Error::base(ErrorType::InvalidKeyType, "Unsupported Public Key Type")
    }

    /// Go's `ErrUnsupportedAlgorithm`.
    pub fn unsupported_algorithm() -> Error {
        Error::base(
            ErrorType::UnsupportedKeyAlgorithm,
            "Unsupported public key algorithm",
        )
    }

    /// Go's `ErrNotSpecImplemented`.
    pub fn not_spec_implemented() -> Error {
        Error::base(
            ErrorType::SpecUnimplemented,
            "This field is not yet supported by the WebAuthn spec",
        )
    }

    /// Go's `ErrNotImplemented`.
    pub fn not_implemented() -> Error {
        Error::base(
            ErrorType::NotImplemented,
            "This field is not yet supported by this library",
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.details)
    }
}

impl std::error::Error for Error {}
