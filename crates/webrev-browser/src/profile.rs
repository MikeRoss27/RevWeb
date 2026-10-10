// crates/webrev-browser/src/profile.rs
//! A disposable browser profile: a throwaway user-data directory plus the
//! launch configuration and the init script that normalises the most trivial
//! headless-automation tells.

use chromiumoxide::browser::BrowserConfig;
use std::path::Path;
use tempfile::TempDir;
use webrev_core::{AuthConfig, OpsecConfig, Result, WebrevError};

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
    profile_dir: TempDir,
}

impl BrowserProfile {
    /// Build a default profile, taking the proxy from the opsec egress policy.
    pub fn from_opsec(opsec: &OpsecConfig) -> Result<Self> {
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
            profile_dir,
        })
    }

    /// Path to the disposable user-data directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.profile_dir.path()
    }

    /// Build the `chromiumoxide` launch configuration for this profile.
    pub fn to_config(&self) -> Result<BrowserConfig> {
        let mut builder = BrowserConfig::builder()
            .user_data_dir(self.profile_dir.path())
            .no_sandbox()
            .arg(format!("--lang={}", self.locale))
            // Chrome exposes automation via this blink feature; disabling it is
            // the standard, documented way to avoid being blocked outright.
            .arg("--disable-blink-features=AutomationControlled".to_owned());
        if let Some(proxy) = &self.proxy {
            builder = builder.arg(format!("--proxy-server={proxy}"));
        }
        builder.build().map_err(WebrevError::Browser)
    }

    /// JavaScript injected before any page script runs, smoothing over the
    /// cheapest headless tells so legitimate analysis is not refused.
    #[must_use]
    pub fn init_script(&self) -> String {
        let vendor = if self.fingerprint_seed % 2 == 0 {
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
    fn config_builds_and_init_script_patches_webdriver() {
        let profile = BrowserProfile::from_opsec(&OpsecConfig::default()).expect("profile");
        // Building the config does not launch a browser, so this is safe in CI.
        assert!(profile.to_config().is_ok());
        let script = profile.init_script();
        assert!(script.contains("navigator, 'webdriver'"));
        assert!(script.contains("en-US"));
        assert!(profile.path().exists());
    }
}
