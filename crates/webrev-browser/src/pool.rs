// crates/webrev-browser/src/pool.rs
//! A small pool that bounds concurrent Chromium instances and reuses idle ones.

use crate::profile::BrowserProfile;
use chromiumoxide::cdp::browser_protocol::target::CreateTargetParams;
use chromiumoxide::{Browser, Page};
use futures::StreamExt;
use std::sync::{Arc, Mutex};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use webrev_core::{Result, WebrevError};

/// A launched browser plus the task driving its CDP event loop.
struct BrowserEntry {
    browser: Browser,
    handler: JoinHandle<()>,
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
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| WebrevError::Browser(format!("browser pool closed: {e}")))?;

        let reused = self.idle.lock().ok().and_then(|mut idle| idle.pop());
        let entry = match reused {
            Some(entry) => entry,
            None => Self::launch(profile).await?,
        };

        Ok(PooledBrowser {
            entry: Some(entry),
            idle: Arc::clone(&self.idle),
            _permit: permit,
        })
    }

    async fn launch(profile: &BrowserProfile) -> Result<BrowserEntry> {
        let config = profile.to_config()?;
        let (browser, mut handler) = Browser::launch(config)
            .await
            .map_err(|e| WebrevError::Browser(format!("launching chromium: {e}")))?;
        // The handler stream must be polled for the browser to function.
        let task = tokio::spawn(async move { while handler.next().await.is_some() {} });
        Ok(BrowserEntry {
            browser,
            handler: task,
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
        for mut entry in entries {
            // The handler task must stay alive for `close` to round-trip over
            // CDP, so it is only aborted after the browser has gone away.
            let _ = entry.browser.close().await;
            let _ = entry.browser.wait().await;
            entry.handler.abort();
        }
    }
}

/// A browser checked out of the pool. Returned to the idle set on drop (the
/// permit is released then too, admitting the next waiter).
pub struct PooledBrowser {
    entry: Option<BrowserEntry>,
    idle: Arc<Mutex<Vec<BrowserEntry>>>,
    _permit: OwnedSemaphorePermit,
}

impl PooledBrowser {
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
            if let Ok(mut idle) = self.idle.lock() {
                idle.push(entry);
            }
        }
    }
}
