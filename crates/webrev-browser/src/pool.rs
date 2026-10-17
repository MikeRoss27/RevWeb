// crates/webrev-browser/src/pool.rs
//! A small pool that bounds concurrent Chromium instances and reuses idle ones.

use crate::egress_proxy::ScopedEgressProxy;
use crate::policy::RefusalLog;
use crate::profile::BrowserProfile;
use chromiumoxide::cdp::browser_protocol::target::CreateTargetParams;
use chromiumoxide::{Browser, Page};
use futures::StreamExt;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use webrev_core::{AuthConfig, Result, Scope, WebrevError};

/// A launched browser plus the task driving its CDP event loop.
struct BrowserEntry {
    browser: Browser,
    handler: JoinHandle<()>,
    identity: BrowserIdentity,
    egress: ScopedEgressProxy,
}

#[derive(PartialEq, Eq)]
struct BrowserIdentity {
    profile_path: PathBuf,
    scope: Scope,
    upstream: Option<String>,
    auth: AuthConfig,
}

impl BrowserIdentity {
    fn new(profile: &BrowserProfile, scope: &Scope) -> Self {
        Self {
            profile_path: profile.path().to_path_buf(),
            scope: scope.clone(),
            upstream: profile.proxy.clone(),
            auth: profile.auth.clone(),
        }
    }
}

/// Bounds the number of live browsers via a semaphore and keeps idle instances
/// for reuse. Cloning the handle shares the same pool.
#[derive(Clone)]
pub struct BrowserPool {
    idle: Arc<Mutex<Vec<BrowserEntry>>>,
    permits: Arc<Semaphore>,
}

impl BrowserPool {
    /// Create a pool allowing at most `max` concurrent browsers (min 1).
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self {
            idle: Arc::new(Mutex::new(Vec::new())),
            permits: Arc::new(Semaphore::new(max.max(1))),
        }
    }

    /// Acquire a browser, reusing an idle one or launching a fresh instance.
    /// Blocks (asynchronously) while the pool is at capacity.
    pub async fn acquire(&self, profile: &BrowserProfile) -> Result<PooledBrowser> {
        self.acquire_with_scope(profile, &profile.scope.clone().unwrap_or_default())
            .await
    }

    /// Reuse only a browser with the same disposable profile, scope and upstream.
    /// A scope-less `acquire` defaults to refusing all network destinations.
    pub async fn acquire_with_scope(
        &self,
        profile: &BrowserProfile,
        scope: &Scope,
    ) -> Result<PooledBrowser> {
        let identity = BrowserIdentity::new(profile, scope);
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| WebrevError::Browser(format!("browser pool closed: {e}")))?;

        let reused = self.idle.lock().ok().and_then(|mut idle| idle.pop());
        let entry = match reused {
            Some(entry) if entry.identity == identity => entry,
            Some(entry) => {
                Self::close_entry(entry).await;
                Self::launch(profile, scope).await?
            }
            None => Self::launch(profile, scope).await?,
        };

        Ok(PooledBrowser {
            entry: Some(entry),
            idle: Arc::clone(&self.idle),
            permit: Some(permit),
            reusable: true,
        })
    }

    async fn launch(profile: &BrowserProfile, scope: &Scope) -> Result<BrowserEntry> {
        let egress = ScopedEgressProxy::start(scope.clone(), profile.proxy.as_deref()).await?;
        let config = profile.to_config_with_proxy(&egress.proxy_url())?;
        let (browser, mut handler) = Browser::launch(config)
            .await
            .map_err(|e| WebrevError::Browser(format!("launching chromium: {e}")))?;
        // The handler stream must be polled for the browser to function.
        let task = tokio::spawn(async move { while handler.next().await.is_some() {} });
        Ok(BrowserEntry {
            browser,
            handler: task,
            identity: BrowserIdentity::new(profile, scope),
            egress,
        })
    }

    /// Gracefully shut the pool down: ask every idle browser to close over CDP
    /// (`Browser.close`), reap its OS process, then stop its event-loop task.
    ///
    /// Call this once the pool is finished with. Letting a
    /// [`chromiumoxide::Browser`] reach its `Drop` without closing it first
    /// logs `Browser was not closed manually ...` and kills Chromium abruptly,
    /// which races the still-running CDP WebSocket handler and surfaces as a
    /// spurious `WS Connection error: ... ConnectionReset` (WSAECONNRESET /
    /// 10054 on Windows). Closing first, waiting for exit, then aborting the
    /// handler avoids both. Errors are ignored: a browser that already exited
    /// needs no further cleanup.
    pub async fn shutdown(&self) {
        let entries: Vec<BrowserEntry> = match self.idle.lock() {
            Ok(mut idle) => std::mem::take(&mut *idle),
            Err(_) => return,
        };
        for entry in entries {
            Self::close_entry(entry).await;
        }
    }

    async fn close_entry(mut entry: BrowserEntry) {
        // Keep the handler and scoped proxy alive until Chromium has exited.
        let _ = entry.browser.close().await;
        let _ = entry.browser.wait().await;
        entry.handler.abort();
    }
}

/// A browser checked out of the pool. Returned to the idle set on drop (the
/// permit is released then too, admitting the next waiter).
pub struct PooledBrowser {
    entry: Option<BrowserEntry>,
    idle: Arc<Mutex<Vec<BrowserEntry>>>,
    permit: Option<OwnedSemaphorePermit>,
    reusable: bool,
}

impl PooledBrowser {
    pub(crate) fn discard(&mut self) {
        self.reusable = false;
    }

    pub(crate) fn take_refusals(&self) -> RefusalLog {
        self.entry
            .as_ref()
            .map(|entry| entry.egress.take_refusals())
            .unwrap_or_default()
    }

    /// Open a new page/tab navigated to `url`.
    pub async fn new_page(&self, url: &str) -> Result<Page> {
        let entry = self
            .entry
            .as_ref()
            .ok_or_else(|| WebrevError::Browser("pooled browser already released".into()))?;
        entry
            .browser
            .new_page(CreateTargetParams::new(url))
            .await
            .map_err(|e| WebrevError::Browser(format!("opening page: {e}")))
    }
}

impl Drop for PooledBrowser {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            if !self.reusable {
                let permit = self.permit.take();
                tokio::spawn(async move {
                    BrowserPool::close_entry(entry).await;
                    drop(permit);
                });
                return;
            }
            if let Ok(mut idle) = self.idle.lock() {
                idle.push(entry);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::OpsecConfig;

    #[test]
    fn identity_requires_same_profile_scope_upstream_and_auth() {
        let mut profile = BrowserProfile::from_opsec(&OpsecConfig::default()).expect("profile");
        let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
        let identity = BrowserIdentity::new(&profile, &scope);
        assert!(identity == BrowserIdentity::new(&profile, &scope));
        assert!(identity != BrowserIdentity::new(&profile, &Scope::default()));
        profile.proxy = Some("http://127.0.0.1:8080".to_owned());
        assert!(identity != BrowserIdentity::new(&profile, &scope));
        profile.proxy = None;
        profile.auth.bearer = Some("different-account".to_owned());
        assert!(identity != BrowserIdentity::new(&profile, &scope));
        let other = BrowserProfile::from_opsec(&OpsecConfig::default()).expect("other profile");
        assert!(identity != BrowserIdentity::new(&other, &scope));
    }

    #[tokio::test]
    #[ignore = "requires a local Chromium/Chrome installation"]
    async fn browser_reuses_only_compatible_scope_and_profile() {
        let pool = BrowserPool::new(1);
        let profile = BrowserProfile::from_opsec(&OpsecConfig::default()).expect("profile");
        let scope = Scope::new(vec!["127.0.0.1".into()], vec![]);
        let first = pool
            .acquire_with_scope(&profile, &scope)
            .await
            .expect("first");
        let first_address = first
            .entry
            .as_ref()
            .expect("entry")
            .browser
            .websocket_address()
            .clone();
        drop(first);
        let reused = pool
            .acquire_with_scope(&profile, &scope)
            .await
            .expect("reuse");
        assert_eq!(
            reused
                .entry
                .as_ref()
                .expect("entry")
                .browser
                .websocket_address(),
            &first_address
        );
        drop(reused);
        let changed = pool
            .acquire_with_scope(&profile, &Scope::default())
            .await
            .expect("new scope");
        assert_ne!(
            changed
                .entry
                .as_ref()
                .expect("entry")
                .browser
                .websocket_address(),
            &first_address
        );
        let changed_address = changed
            .entry
            .as_ref()
            .expect("entry")
            .browser
            .websocket_address()
            .clone();
        drop(changed);
        let other = BrowserProfile::from_opsec(&OpsecConfig::default()).expect("other profile");
        let isolated = pool
            .acquire_with_scope(&other, &Scope::default())
            .await
            .expect("other identity");
        assert_ne!(
            isolated
                .entry
                .as_ref()
                .expect("entry")
                .browser
                .websocket_address(),
            &changed_address
        );
        drop(isolated);
        pool.shutdown().await;
    }
}
