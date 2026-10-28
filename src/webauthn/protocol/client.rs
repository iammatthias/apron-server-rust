use rust_stdlib::net::url::{self, Url};
use rust_stdlib_crypto::subtle;
use rust_stdlib_derive::Deserialize;

use super::{CeremonyType, Error, TopOriginVerificationMode};

/// Go's `CollectedClientData` (§5.8.1), decoded with `encoding/json` v1
/// rules: member names match case-insensitively and unknown members are
/// ignored.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct CollectedClientData {
    #[json("type")]
    pub kind: CeremonyType,
    #[json("challenge")]
    pub challenge: String,
    #[json("origin")]
    pub origin: String,
    #[json("topOrigin,omitempty")]
    pub top_origin: String,
    #[json("crossOrigin,omitempty")]
    pub cross_origin: bool,
    #[json("tokenBinding,omitempty")]
    pub token_binding: Option<TokenBinding>,
    #[json("new_keys_may_be_added_here,omitempty")]
    pub hint: String,
}

/// Go's `TokenBinding`.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct TokenBinding {
    #[json("status")]
    pub status: String,
    #[json("id,omitempty")]
    pub id: String,
}

impl CollectedClientData {
    /// Go's `CollectedClientData.Verify`: steps 7 to 10 of §7.1 and 8 to 11
    /// of §7.2.
    pub fn verify(
        &self,
        stored_challenge: &str,
        ceremony: &CeremonyType,
        rp_origins: &[String],
        rp_top_origins: &[String],
        rp_top_origins_verify: TopOriginVerificationMode,
        allow_cross_origin: bool,
    ) -> Result<(), Error> {
        if self.kind != *ceremony {
            return Err(Error::verification()
                .with_details("Error validating ceremony type")
                .with_info(format!(
                    "Expected Value: {ceremony}, Received: {}",
                    self.kind
                )));
        }
        if subtle::constant_time_compare(stored_challenge.as_bytes(), self.challenge.as_bytes())
            != 1
        {
            return Err(Error::verification()
                .with_details("Error validating challenge")
                .with_info(format!(
                    "Expected b Value: {stored_challenge:?}\nReceived b: {:?}\n",
                    self.challenge
                )));
        }
        if !is_origin_in_haystack(&self.origin, rp_origins) {
            return Err(Error::verification()
                .with_details("Error validating origin")
                .with_info(format!(
                    "Expected Values: [{}], Received: {}",
                    rp_origins.join(" "),
                    self.origin
                )));
        }
        if !allow_cross_origin && self.cross_origin {
            return Err(Error::verification()
                .with_details("Error validating cross origin flag")
                .with_info("The cross origin flag is invalid due to the configuration."));
        }
        if !self.top_origin.is_empty() {
            if !self.cross_origin {
                return Err(Error::verification()
                    .with_details("Error validating topOrigin")
                    .with_info("The topOrigin can't have values unless crossOrigin is true."));
            }
            let possible: Vec<String> = match rp_top_origins_verify {
                TopOriginVerificationMode::Explicit => rp_top_origins.to_vec(),
                TopOriginVerificationMode::Auto => {
                    rp_top_origins.iter().chain(rp_origins).cloned().collect()
                }
                TopOriginVerificationMode::Implicit => rp_origins.to_vec(),
                TopOriginVerificationMode::Default => {
                    return Err(Error::not_implemented()
                        .with_details("Error handling unknown Top Origin verification mode"))
                }
            };
            if !is_origin_in_haystack(&self.top_origin, &possible) {
                return Err(Error::verification()
                    .with_details("Error validating top origin")
                    .with_info(format!(
                        "Expected Values: [{}], Received: {}",
                        possible.join(" "),
                        self.top_origin
                    )));
            }
        }
        if let Some(binding) = &self.token_binding {
            if binding.status.is_empty() {
                return Err(Error::parsing_data().with_details(
                    "Error decoding clientData, token binding present without status",
                ));
            }
            if !matches!(
                binding.status.as_str(),
                "present" | "supported" | "not-supported"
            ) {
                return Err(Error::parsing_data()
                    .with_details(
                        "Error decoding clientData, token binding present with invalid status",
                    )
                    .with_info(format!("Got: {}", binding.status)));
            }
        }
        Ok(())
    }
}

/// Go's `IsOriginInHaystack`: an `http` or `https` origin matches one with
/// the same scheme and host, ignoring case and a default port; anything else
/// must match exactly.
pub fn is_origin_in_haystack(needle: &str, haystack: &[String]) -> bool {
    match parse_origin_uri(needle) {
        Some(needle) => haystack.iter().any(|hay| {
            parse_origin_uri(hay).is_some_and(|hay| {
                needle.scheme.eq_ignore_ascii_case(&hay.scheme)
                    && needle.host.to_lowercase() == hay.host.to_lowercase()
            })
        }),
        None => haystack.iter().any(|hay| hay == needle),
    }
}

fn parse_origin_uri(raw: &str) -> Option<Url> {
    let lower = raw.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return None;
    }
    let mut uri = url::parse(raw).ok()?;
    let default_port = match uri.scheme.as_str() {
        "http" => "80",
        "https" => "443",
        _ => "",
    };
    if !default_port.is_empty() && uri.port() == default_port {
        uri.host = uri.hostname();
    }
    Some(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn origin_in_haystack() {
        // client_test.go TestIsOriginInHaystack.
        let cases: &[(&str, &[&str], bool)] = &[
            ("https://example.com", &["https://example.com"], true),
            ("https://example.com:443", &["https://example.com"], true),
            ("https://example.com", &["https://example.com:443"], true),
            ("http://example.com:80", &["http://example.com"], true),
            ("https://EXAMPLE.com", &["https://example.com"], true),
            ("HTTPS://example.com", &["https://example.com"], true),
            ("https://example.com/path", &["https://example.com"], true),
            ("https://example.com:8443", &["https://example.com"], false),
            ("http://example.com", &["https://example.com"], false),
            ("https://example.com:80", &["https://example.com"], false),
            ("https://evil.example", &["https://example.com"], false),
            (
                "android:apk-key-hash:abc",
                &["android:apk-key-hash:abc"],
                true,
            ),
            (
                "android:apk-key-hash:abc",
                &["android:apk-key-hash:ABC"],
                false,
            ),
            ("https://[::1]:443", &["https://[::1]"], false),
            ("https://[::1]", &["https://[::1]"], true),
            ("", &[], false),
        ];
        for (needle, haystack, want) in cases {
            assert_eq!(
                is_origin_in_haystack(needle, &strings(haystack)),
                *want,
                "{needle} in {haystack:?}"
            );
        }
    }
}
