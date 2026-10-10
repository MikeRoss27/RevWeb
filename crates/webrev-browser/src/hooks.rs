// crates/webrev-browser/src/hooks.rs
//! JavaScript injected into every page to observe `fetch` and `XMLHttpRequest`
//! calls, recording each into `window.__webrev` for later collection.

use serde::Deserialize;

/// Installed via `evaluate_on_new_document` so it runs before page scripts.
/// It wraps `fetch` and `XHR.open`, pushing `{method, url, trigger}` records
/// onto `window.__webrev` without altering behaviour. `window.__webrev_trigger`
/// is a label the active-interaction driver sets immediately before clicking
/// an element and clears right after, so any call recorded in between can be
/// attributed to the UI action that caused it (the before/after "diff" that
/// turns a flat endpoint list into "clicking Delete Account calls DELETE
/// /api/account").
pub const INSTALL_HOOKS: &str = r"(() => {
  window.__webrev = window.__webrev || [];
  window.__webrev_trigger = null;
  const record = (method, url) => {
    try {
      window.__webrev.push({
        method: String(method || 'GET'),
        url: String(url),
        trigger: window.__webrev_trigger || null,
      });
    }
    catch (e) { /* never break the page */ }
  };
  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = function (input, init) {
      const url = (typeof input === 'string') ? input : (input && input.url);
      const method = (init && init.method) || (input && input.method) || 'GET';
      record(method, url);
      return origFetch.apply(this, arguments);
    };
  }
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    record(method, url);
    return origOpen.apply(this, arguments);
  };
})();";

/// Evaluated after the dwell period to read back the recorded calls as JSON.
pub const COLLECT_HOOKS: &str = "JSON.stringify(window.__webrev || [])";

/// One recorded call, deserialized from the JSON produced by [`COLLECT_HOOKS`].
#[derive(Debug, Clone, Deserialize)]
pub struct HookRecord {
    pub method: String,
    pub url: String,
    /// The UI element (label derived from its id/aria-label/text) whose click
    /// was in flight when this call fired, if any. `None` for calls fired
    /// outside an attributed click (page load, timers, scroll handlers).
    #[serde(default)]
    pub trigger: Option<String>,
}
