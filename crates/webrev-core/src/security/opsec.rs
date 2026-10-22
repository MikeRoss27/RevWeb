// crates/webrev-core/src/security/opsec.rs
//! Operational configuration shared by the fetch stage and the browser.
//!
//! These settings keep legitimate authorized testing from being trivially
//! blocked (rate limiting, rotating a small UA pool, optional egress proxy) and
//! bound the request cadence. They are deliberately conservative defaults, not
//! an evasion toolkit: there is no spoofing of target identity, only polite,
//! configurable traffic shaping.

use crate::model::session::Mission;
use crate::security::auth::AuthConfig;
use crate::security::sanitize::redact_url;
use serde::{Deserialize, Serialize};

/// How outbound requests leave the host.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPolicy {
    /// Optional proxy URL (e.g. `http://127.0.0.1:8080` for an intercepting
    /// proxy during an engagement). `None` means direct.
    pub proxy: Option<String>,
    /// Whether direct (non-proxied) egress is permitted when `proxy` is `None`.
    /// Fail-closed engagements set this to `false` together with a proxy.
    pub allow_direct: bool,
}

/// `Debug` masks proxy userinfo (`user:pass@`) and token-like query values.
impl std::fmt::Debug for EgressPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressPolicy")
            .field("proxy", &self.proxy.as_deref().map(redact_url))
            .field("allow_direct", &self.allow_direct)
            .finish()
    }
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            proxy: None,
            allow_direct: true,
        }
    }
}

/// DNS resolution strategy.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsPolicy {
    /// Use the system resolver.
    #[default]
    System,
    /// Resolve via DNS-over-HTTPS at the given endpoint.
    DnsOverHttps(String),
}

impl std::fmt::Debug for DnsPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System => f.write_str("System"),
            Self::DnsOverHttps(url) => f
                .debug_tuple("DnsOverHttps")
                .field(&redact_url(url))
                .finish(),
        }
    }
}

/// User-agent rotation policy. The pool defaults to a single current Chrome UA;
/// rotation simply cycles whatever strings the operator provides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationPolicy {
    pub user_agents: Vec<String>,
    /// Rotate to the next UA after this many requests (0 disables rotation).
    pub rotate_every: u32,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            user_agents: vec![concat!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ",
                "AppleWebKit/537.36 (KHTML, like Gecko) ",
                "Chrome/131.0.0.0 Safari/537.36"
            )
            .to_owned()],
            rotate_every: 0,
        }
    }
}

impl RotationPolicy {
    /// Select a user agent for the given request index, honoring `rotate_every`.
    /// Returns `None` only when the pool is empty.
    #[must_use]
    pub fn user_agent_for(&self, request_index: u32) -> Option<&str> {
        if self.user_agents.is_empty() {
            return None;
        }
        let idx = match request_index.checked_div(self.rotate_every) {
            // `rotate_every == 0` => checked_div is None => rotation disabled.
            None => 0,
            Some(step) => step as usize % self.user_agents.len(),
        };
        self.user_agents.get(idx).map(String::as_str)
    }
}

/// Request-cadence and egress configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ActiveLimits {
    /// Shared by every active check, including controls and failed requests.
    pub max_requests: usize,
    /// Decoded response body limit; larger responses remain inconclusive.
    pub max_body_bytes: usize,
    /// Individual query positions per endpoint (duplicate names stay distinct).
    pub max_parameters: usize,
    /// Opt-in, off by default: allows the timing-based command-injection probe
    /// (`active::timing`) to actually execute a sleep on the target if the
    /// parameter is vulnerable. Every other active probe is GET-shaped and
    /// never executes OS commands, writes files or triggers callbacks
    /// (`docs/security.md`, "Probe behavior"); this is the one documented
    /// exception, gated so it is never run without explicit consent
    /// (`--allow-timing-probes`).
    pub allow_timing_probes: bool,
}

impl Default for ActiveLimits {
    fn default() -> Self {
        Self {
            max_requests: 200,
            max_body_bytes: 512 * 1024,
            max_parameters: 4,
            allow_timing_probes: false,
        }
    }
}

/// Request-cadence and egress configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsecConfig {
    pub egress: EgressPolicy,
    pub dns: DnsPolicy,
    pub rotation: RotationPolicy,
    /// Lower bound of inter-request delay, in milliseconds.
    pub delay_min_ms: u64,
    /// Upper bound of inter-request delay, in milliseconds.
    pub delay_max_ms: u64,
    /// Maximum concurrent in-flight requests.
    pub max_concurrency: usize,
    /// Maximum number of resources fetched in one crawl (hard budget).
    pub max_pages: usize,
    /// Maximum link-following depth from the seeds (0 = seeds only).
    pub max_depth: usize,
    /// Decoded crawl response body limit, per page. Larger responses are
    /// truncated to this many bytes rather than read to completion: a
    /// pathologically large or slow-drip response must not grow the
    /// fetch stage's memory without bound. Distinct from
    /// `active.max_body_bytes`, which bounds active-probe responses and is
    /// deliberately much smaller (a probe's proof is a short excerpt; a
    /// crawled page can legitimately be a multi-megabyte bundle).
    #[serde(default = "default_crawl_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Authentication material applied to in-scope requests.
    pub auth: AuthConfig,
    #[serde(default)]
    pub active: ActiveLimits,
}

/// 20 MiB: generous enough for a real-world minified SPA bundle with an
/// inlined source map, small enough to bound a pathological response.
fn default_crawl_max_body_bytes() -> usize {
    20 * 1024 * 1024
}

impl Default for OpsecConfig {
    fn default() -> Self {
        Self {
            egress: EgressPolicy::default(),
            dns: DnsPolicy::default(),
            rotation: RotationPolicy::default(),
            delay_min_ms: 150,
            delay_max_ms: 600,
            max_concurrency: 4,
            max_body_bytes: default_crawl_max_body_bytes(),
            max_pages: 50,
            max_depth: 2,
            auth: AuthConfig::default(),
            active: ActiveLimits::default(),
        }
    }
}

impl OpsecConfig {
    /// Validate internal consistency of the delay window.
    #[must_use]
    pub fn delay_window(&self) -> (u64, u64) {
        let lo = self.delay_min_ms.min(self.delay_max_ms);
        let hi = self.delay_min_ms.max(self.delay_max_ms);
        (lo, hi)
    }
}

/// A mission plus its operational configuration — the top-level object the CLI
/// and TUI hand to the pipeline and browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissionProfile {
    pub mission: Mission,
    pub opsec: OpsecConfig,
}

impl MissionProfile {
    #[must_use]
    pub fn new(mission: Mission, opsec: OpsecConfig) -> Self {
        Self { mission, opsec }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_masks_proxy_userinfo_and_auth_values() {
        let cfg = OpsecConfig {
            egress: EgressPolicy {
                proxy: Some("http://op:proxy-pass-9@127.0.0.1:8080".into()),
                allow_direct: false,
            },
            dns: DnsPolicy::DnsOverHttps("https://dns.test/q?token=doh-secret-8".into()),
            auth: AuthConfig {
                bearer: Some("bearer-secret-7".into()),
                ..AuthConfig::default()
            },
            ..OpsecConfig::default()
        };
        let shown = format!("{cfg:?} {cfg:#?}");
        for secret in ["proxy-pass-9", "doh-secret-8", "bearer-secret-7", "op:"] {
            assert!(!shown.contains(secret), "{secret} leaked: {shown}");
        }
        assert!(shown.contains("127.0.0.1:8080"));
    }

    #[test]
    fn rotation_cycles_with_period() {
        let rot = RotationPolicy {
            user_agents: vec!["a".into(), "b".into()],
            rotate_every: 2,
        };
        assert_eq!(rot.user_agent_for(0), Some("a"));
        assert_eq!(rot.user_agent_for(1), Some("a"));
        assert_eq!(rot.user_agent_for(2), Some("b"));
        assert_eq!(rot.user_agent_for(4), Some("a"));
    }

    #[test]
    fn rotation_disabled_pins_first() {
        let rot = RotationPolicy {
            user_agents: vec!["a".into(), "b".into()],
            rotate_every: 0,
        };
        assert_eq!(rot.user_agent_for(99), Some("a"));
    }

    #[test]
    fn delay_window_is_ordered() {
        let cfg = OpsecConfig {
            delay_min_ms: 900,
            delay_max_ms: 100,
            ..OpsecConfig::default()
        };
        assert_eq!(cfg.delay_window(), (100, 900));
    }
}
