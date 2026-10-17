// crates/webrev-browser/src/profile.rs
//! A disposable browser profile: a throwaway user-data directory plus the
//! launch configuration and the init script that normalises the most trivial
//! headless-automation tells.

use crate::policy::InteractionPolicy;
use chromiumoxide::browser::BrowserConfig;
use std::path::Path;
use tempfile::TempDir;
use webrev_core::{AuthConfig, OpsecConfig, Result, Scope, WebrevError};

/// Per-run browser identity. The `TempDir` is deleted when the profile drops,
/// so no cookies, cache, or local storage survive a run.
pub struct BrowserProfile {
    pub timezone: String,
    pub locale: String,
    /// Optional `(latitude, longitude)` geolocation override.
    pub geolocation: Option<(f64, f64)>,
    /// Seed for deterministic, per-run fingerprint jitter (WebGL vendor, etc.).
    pub fingerprint_seed: u64,
    /// Optional egress proxy (`--proxy-server`).
    pub proxy: Option<String>,
    /// Authentication material applied as extra HTTP headers.
    pub auth: AuthConfig,
    /// Authorization boundary applied to every browser request.
    pub scope: Option<Scope>,
    /// Explicit opt-in observation policy; exploration remains the default.
    pub interaction_policy: InteractionPolicy,
    profile_dir: TempDir,
}

impl BrowserProfile {
    /// Build a default profile, taking the proxy from the opsec egress policy.
    pub fn from_opsec(opsec: &OpsecConfig) -> Result<Self> {
        if !opsec.egress.allow_direct && opsec.egress.proxy.is_none() {
            return Err(WebrevError::Config(
                "browser egress requires an upstream proxy when direct egress is disabled"
                    .to_owned(),
            ));
        }
        let profile_dir = tempfile::Builder::new()
            .prefix("webrev-profile-")
            .tempdir()
            .map_err(WebrevError::Io)?;
        Ok(Self {
            timezone: "UTC".to_owned(),
            locale: "en-US".to_owned(),
            geolocation: None,
            fingerprint_seed: rand::random(),
            proxy: opsec.egress.proxy.clone(),
            auth: opsec.auth.clone(),
            scope: None,
            interaction_policy: InteractionPolicy::default(),
            profile_dir,
        })
    }

    #[must_use]
    pub fn with_scope(mut self, scope: Scope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Disable driven interactions and refuse potentially mutating HTTP methods.
    /// GET requests and page scripts can still have application side effects.
    #[must_use]
    pub fn with_interaction_policy(mut self, policy: InteractionPolicy) -> Self {
        self.interaction_policy = policy;
        self
    }

    /// Path to the disposable user-data directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.profile_dir.path()
    }

    /// Build the `chromiumoxide` launch configuration for this profile.
    pub fn to_config(&self) -> Result<BrowserConfig> {
        self.build_config(self.proxy.as_deref())
    }

    /// Pool-only configuration: every HTTP/CONNECT/WebSocket request traverses
    /// the lifetime-bound scope guard, including Chromium's implicit loopback bypass.
    pub(crate) fn to_config_with_proxy(&self, proxy: &str) -> Result<BrowserConfig> {
        self.build_config(Some(proxy))
    }

    fn build_config(&self, proxy: Option<&str>) -> Result<BrowserConfig> {
        let mut builder = BrowserConfig::builder()
            .user_data_dir(self.profile_dir.path())
            .no_sandbox()
            .enable_request_intercept()
            .arg(("lang", self.locale.as_str()))
            // Chrome exposes automation via this blink feature; disabling it is
            // the standard, documented way to avoid being blocked outright.
            .arg(("disable-blink-features", "AutomationControlled"));
        if let Some(proxy) = proxy {
            // chromiumoxide prepends `--` itself, so flags go in as (key, value).
            builder = builder
                .arg(("proxy-server", proxy))
                .arg(("proxy-bypass-list", "<-loopback>"));
        }
        builder.build().map_err(WebrevError::Browser)
    }

    /// JavaScript injected before any page script runs, smoothing over the
    /// cheapest headless tells so legitimate analysis is not refused.
    #[must_use]
    pub fn init_script(&self) -> String {
        let vendor = if self.fingerprint_seed.is_multiple_of(2) {
            "Intel Inc."
        } else {
            "Google Inc."
        };
        format!(
            r"(() => {{
  Object.defineProperty(navigator, 'webdriver', {{ get: () => undefined }});
  Object.defineProperty(navigator, 'languages', {{ get: () => ['{lang}', 'en'] }});
  window.chrome = window.chrome || {{ runtime: {{}} }};
  const VENDOR = '{vendor}';
  const getParameter = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function (p) {{
    if (p === 37445) return VENDOR;            // UNMASKED_VENDOR_WEBGL
    if (p === 37446) return 'webrev-renderer'; // UNMASKED_RENDERER_WEBGL
    return getParameter.call(this, p);
  }};
}})();",
            lang = self.locale,
            vendor = vendor,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_egress_disabled_requires_upstream() {
        let mut opsec = OpsecConfig::default();
        opsec.egress.allow_direct = false;
        assert!(BrowserProfile::from_opsec(&opsec).is_err());
        opsec.egress.proxy = Some("http://127.0.0.1:8080".to_owned());
        assert!(BrowserProfile::from_opsec(&opsec).is_ok());
    }

    #[test]
    fn config_builds_and_init_script_patches_webdriver() {
        let profile = BrowserProfile::from_opsec(&OpsecConfig::default()).expect("profile");
        // Building requires a locally installed browser binary, even though it
        // does not launch it. Validate either successful config or the exact
        // missing-browser diagnostic so non-browser CI remains deterministic.
        if let Err(error) = profile.to_config() {
            assert!(error
                .to_string()
                .contains("Could not auto detect a chrome executable"));
        }
        let script = profile.init_script();
        assert!(script.contains("navigator, 'webdriver'"));
        assert!(script.contains("en-US"));
        assert!(profile.path().exists());
    }
}
