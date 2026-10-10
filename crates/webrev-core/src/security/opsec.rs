// crates/webrev-core/src/opsec.rs
//! Operational configuration shared by the fetch stage and the browser.
//!
//! These settings keep legitimate authorized testing from being trivially
//! blocked (rate limiting, rotating a small UA pool, optional egress proxy) and
//! bound the request cadence. They are deliberately conservative defaults, not
//! an evasion toolkit: there is no spoofing of target identity, only polite,
//! configurable traffic shaping.

use crate::model::session::Mission;
use crate::security::auth::AuthConfig;
use serde::{Deserialize, Serialize};

/// How outbound requests leave the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPolicy {
    /// Optional proxy URL (e.g. `http://127.0.0.1:8080` for an intercepting
    /// proxy during an engagement). `None` means direct.
    pub proxy: Option<String>,
    /// Whether direct (non-proxied) egress is permitted when `proxy` is `None`.
    /// Fail-closed engagements set this to `false` together with a proxy.
    pub allow_direct: bool,
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsPolicy {
    /// Use the system resolver.
    #[default]
    System,
    /// Resolve via DNS-over-HTTPS at the given endpoint.
    DnsOverHttps(String),
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
    /// Authentication material applied to in-scope requests.
    pub auth: AuthConfig,
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
            max_pages: 50,
            max_depth: 2,
            auth: AuthConfig::default(),
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
