use rust_stdlib::net::{self, url};
use rust_stdlib::strconv;

const MAX_DOMAIN_LENGTH: usize = 253;
const MAX_DOMAIN_LABEL_LENGTH: usize = 63;
const FORBIDDEN_DOMAIN_CODE_POINTS: &str = " #/:<>?@[\\]^|%";
const MAXIMUM_PORT: u64 = 65535;

/// Go's `ValidateRPID`: the RP ID must be a bare domain (§5.1.2), with an
/// error text naming the first rule it breaks.
pub fn validate_rpid(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("empty value provided".into());
    }
    if net::ip::parse_ip(value).is_some() {
        return Err("the value must be a domain and not an IP address".into());
    }
    let rpid = url::parse(value).map_err(|err| err.to_string())?;
    if !rpid.scheme.is_empty() && !rpid.opaque.is_empty() && rpid.path.is_empty() {
        return Err("the port component must be empty".into());
    }
    if !rpid.scheme.is_empty() {
        let host = !rpid.host.is_empty();
        if host && !rpid.path.is_empty() {
            return Err("the path component must be empty".into());
        }
        if host && !rpid.raw_query.is_empty() {
            return Err("the query component must be empty".into());
        }
        if host && !rpid.fragment.is_empty() {
            return Err("the fragment component must be empty".into());
        }
        if host && !rpid.port().is_empty() {
            return Err("the port component must be empty".into());
        }
        return Err("the scheme component must be empty".into());
    }
    if !rpid.raw_query.is_empty() {
        return Err("the query component must be empty".into());
    }
    if !rpid.raw_fragment.is_empty() || !rpid.fragment.is_empty() {
        return Err("the fragment component must be empty".into());
    }
    if rpid.host.is_empty() && rpid.path.contains('/') {
        return Err("the path component must be empty".into());
    }
    validate_domain_string(value)
}

fn validate_domain_string(value: &str) -> Result<(), String> {
    if value.len() > MAX_DOMAIN_LENGTH {
        return Err("the domain must not exceed 253 characters".into());
    }
    let labels: Vec<&str> = value.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err("the domain must not contain an empty label".into());
        }
        if label.len() > MAX_DOMAIN_LABEL_LENGTH {
            return Err("the domain labels must not exceed 63 characters".into());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("the domain labels must not begin or end with a hyphen".into());
        }
        if label.contains(|c| FORBIDDEN_DOMAIN_CODE_POINTS.contains(c)) {
            return Err("the domain must not contain a forbidden character".into());
        }
        for c in label.chars() {
            if c < '\u{20}' || c == '\u{7f}' {
                return Err("the domain must not contain a forbidden character".into());
            }
            if c > '\u{7f}' {
                return Err("the domain must not contain non-ascii characters, apply IDNA normalization to it first".into());
            }
        }
    }
    if is_numeric_domain_label(labels[labels.len() - 1]) {
        return Err("the final domain label must not be a number".into());
    }
    if labels.len() == 1 && value != "localhost" {
        return Err("the domain component must actually be a domain".into());
    }
    Ok(())
}

/// Go's `isNumericDomainLabel`, whose `ParseUint(label, 0, 64)` also counts
/// prefixed and underscored forms such as `0x1a` as numbers.
fn is_numeric_domain_label(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    label.bytes().all(|b| b.is_ascii_digit()) || strconv::parse_uint(label, 0, 64).is_ok()
}

/// Go's `IsOpaqueOrigin`: an origin that is not an absolute http or https URL
/// with a host and a valid port.
pub fn is_opaque_origin(origin: &str) -> bool {
    let Ok(uri) = url::parse(origin) else {
        return true;
    };
    if uri.scheme.is_empty() {
        return true;
    }
    if !matches!(uri.scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return true;
    }
    if uri.hostname().is_empty() {
        return true;
    }
    let port = uri.port();
    !port.is_empty() && port.parse::<u64>().map_or(true, |n| n > MAXIMUM_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rpid() {
        // utils_test.go TestValidateRPID, the cases of the subset.
        for ok in [
            "localhost",
            "example.com",
            "a.example.com",
            "xn--bcher-kva.example",
            "1.example",
        ] {
            assert_eq!(validate_rpid(ok), Ok(()), "{ok}");
        }
        let cases = [
            ("", "empty value provided"),
            ("127.0.0.1", "the value must be a domain and not an IP address"),
            ("::1", "the value must be a domain and not an IP address"),
            ("https://example.com", "the scheme component must be empty"),
            ("https://example.com/path", "the path component must be empty"),
            ("https://example.com:443", "the port component must be empty"),
            ("example.com:443", "the port component must be empty"),
            ("example.com/path", "the path component must be empty"),
            ("example.com?x=1", "the query component must be empty"),
            ("example.com#x", "the fragment component must be empty"),
            ("example..com", "the domain must not contain an empty label"),
            ("-example.com", "the domain labels must not begin or end with a hyphen"),
            ("exa mple.com", "the domain must not contain a forbidden character"),
            ("bücher.example", "the domain must not contain non-ascii characters, apply IDNA normalization to it first"),
            ("example.123", "the final domain label must not be a number"),
            ("example.0x1a", "the final domain label must not be a number"),
            ("example", "the domain component must actually be a domain"),
        ];
        for (value, want) in cases {
            assert_eq!(validate_rpid(value).unwrap_err(), want, "{value:?}");
        }
        assert_eq!(
            validate_rpid(&format!("{}.com", "a".repeat(64))).unwrap_err(),
            "the domain labels must not exceed 63 characters"
        );
    }

    #[test]
    fn opaque_origins() {
        for opaque in [
            "android:apk-key-hash:abc",
            "file://",
            "chrome-extension://x/",
            "https://",
            "https://example.com:70000",
            "example.com",
        ] {
            assert!(is_opaque_origin(opaque), "{opaque}");
        }
        for origin in [
            "https://example.com",
            "http://localhost:8080",
            "HTTPS://Example.com:443",
        ] {
            assert!(!is_opaque_origin(origin), "{origin}");
        }
    }
}
