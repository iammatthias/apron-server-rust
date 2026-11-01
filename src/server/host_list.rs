//! Host lists, as apron-server-cloudflare's `PUSH_HOSTS` and
//! `OG_MEDIA_HOSTS` read them: exact host names, `*.host` for a host's
//! subdomains only, or a standalone `*` for any host.

use rust_stdlib::net::url;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostList {
    Any,
    /// Exact host names, and `*.` suffixes, lowercase.
    Listed(Vec<String>),
}

impl HostList {
    pub fn of(hosts: &[&str]) -> HostList {
        HostList::Listed(hosts.iter().map(|h| (*h).to_owned()).collect())
    }

    /// Reads a list flag's entries, each one or more comma-separated hosts;
    /// `None` when they name no host. `flag` names the flag in the error.
    pub fn parse(entries: &[String], flag: &str) -> Result<Option<HostList>, String> {
        let hosts: Vec<String> = entries
            .iter()
            .flat_map(|entry| entry.split(','))
            .map(|host| host.trim().to_ascii_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
        if hosts.is_empty() {
            return Ok(None);
        }
        if hosts == ["*"] {
            return Ok(Some(HostList::Any));
        }
        for host in &hosts {
            if !valid_host_pattern(host) {
                return Err(format!(
                    "invalid {flag} {}: list host names, *.host suffixes, or a standalone *",
                    rust_stdlib::strconv::quote(host)
                ));
            }
        }
        Ok(Some(HostList::Listed(hosts)))
    }

    /// Whether a host, lowercase without a trailing dot, is one of these.
    pub fn allows(&self, host: &str) -> bool {
        match self {
            HostList::Any => true,
            HostList::Listed(hosts) => hosts.iter().any(|entry| match entry.strip_prefix('*') {
                Some(suffix) => host.ends_with(suffix),
                None => host == entry,
            }),
        }
    }

    pub fn allows_url(&self, endpoint: &str) -> bool {
        url::parse(endpoint).is_ok_and(|u| self.allows(&u.hostname().to_ascii_lowercase()))
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, HostList::Listed(hosts) if hosts.is_empty())
    }
}

/// `^(\*\.)?label(\.label)+$`, each label letters, digits and inner `-`.
fn valid_host_pattern(host: &str) -> bool {
    let name = host.strip_prefix("*.").unwrap_or(host);
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// An empty list, which allows no host.
impl Default for HostList {
    fn default() -> HostList {
        HostList::Listed(Vec::new())
    }
}
