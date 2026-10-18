// crates/webrev-cli/src/logging.rs
//! Stderr logging setup.
//!
//! The default filter is `info`. `RUST_LOG`, when set, replaces it, but a few
//! dependency targets are clamped afterwards because they dump wire data that
//! contains credentials (measured against a fixture on 2026-10-18):
//!
//! - `chromiumoxide::conn` logs raw CDP messages at `debug`/`trace`:
//!   `Authorization` and `Cookie` values from `Network.*ExtraInfo`, the
//!   `Set-Cookie` response headers and session cookies.
//! - `tungstenite` logs the same WebSocket frames at `trace`.
//!
//! `reqwest` and `hyper` were measured and logged host and port only, so they
//! are not clamped. Setting `WEBREV_LOG_UNSAFE=1` lifts the clamp for
//! debugging against disposable credentials.

use tracing_subscriber::{fmt, EnvFilter};

/// Env var that lifts the clamp on wire-data targets.
pub const UNSAFE_ENV: &str = "WEBREV_LOG_UNSAFE";

/// Directives applied after the user's filter. Later directives for the same
/// target replace earlier ones.
const CLAMPS: [&str; 2] = ["chromiumoxide::conn=error", "tungstenite=error"];

/// Default when `RUST_LOG` is unset. Silences `chromiumoxide::handler`'s benign
/// WARN flood ("WS Invalid message: data did not match any variant of untagged
/// enum Message"), emitted once per unrecognised CDP event when the installed
/// Chrome is newer than the CDP types the crate knows. Genuine handler errors
/// stay visible.
const DEFAULT_FILTER: &str = "info,chromiumoxide::handler=error";

/// Builds the filter from an optional `RUST_LOG` value.
pub fn build_filter(rust_log: Option<&str>, allow_unsafe: bool) -> EnvFilter {
    let mut filter = rust_log
        .and_then(|raw| EnvFilter::try_new(raw).ok())
        .unwrap_or_else(|| EnvFilter::new(DEFAULT_FILTER));
    if !allow_unsafe {
        for clamp in CLAMPS {
            if let Ok(directive) = clamp.parse() {
                filter = filter.add_directive(directive);
            }
        }
    }
    filter
}

/// Installs the stderr subscriber.
pub fn init() {
    let rust_log = std::env::var("RUST_LOG").ok();
    let allow_unsafe = std::env::var(UNSAFE_ENV).is_ok_and(|v| v == "1");
    let _ = fmt()
        .with_env_filter(build_filter(rust_log.as_deref(), allow_unsafe))
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::build_filter;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::{fmt, fmt::MakeWriter};

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Emits one event per sensitive and benign target and returns the log.
    fn run(rust_log: Option<&str>, allow_unsafe: bool) -> String {
        let capture = Capture::default();
        let subscriber = fmt()
            .with_env_filter(build_filter(rust_log, allow_unsafe))
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::trace!(target: "chromiumoxide::conn", "CDP-RAW-FRAME");
            tracing::debug!(
                target: "chromiumoxide::conn::raw_ws::parse_errors",
                "CDP-PARSE-ERROR"
            );
            tracing::trace!(target: "tungstenite::protocol", "WS-FRAME");
            tracing::debug!(target: "reqwest::connect", "REQWEST-CONNECT");
            tracing::debug!(target: "webrev_pipeline", "OWN-DEBUG");
        });
        let bytes = capture.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }

    #[test]
    fn debug_and_trace_do_not_reach_wire_data_targets() {
        for level in ["debug", "trace"] {
            let log = run(Some(level), false);
            assert!(!log.contains("CDP-RAW-FRAME"), "{level}: {log}");
            assert!(!log.contains("CDP-PARSE-ERROR"), "{level}: {log}");
            assert!(!log.contains("WS-FRAME"), "{level}: {log}");
            assert!(log.contains("REQWEST-CONNECT"), "{level}: {log}");
            assert!(log.contains("OWN-DEBUG"), "{level}: {log}");
        }
    }

    #[test]
    fn explicit_target_directive_cannot_reopen_the_clamp() {
        let log = run(
            Some("trace,chromiumoxide::conn=trace,tungstenite=trace"),
            false,
        );
        assert!(!log.contains("CDP-RAW-FRAME"), "{log}");
        assert!(!log.contains("CDP-PARSE-ERROR"), "{log}");
        assert!(!log.contains("WS-FRAME"), "{log}");
    }

    #[test]
    fn opt_in_lifts_the_clamp() {
        let log = run(Some("trace"), true);
        assert!(log.contains("CDP-RAW-FRAME"), "{log}");
        assert!(log.contains("WS-FRAME"), "{log}");
    }

    #[test]
    fn default_filter_hides_debug() {
        let log = run(None, false);
        assert!(!log.contains("REQWEST-CONNECT"), "{log}");
        assert!(!log.contains("CDP-RAW-FRAME"), "{log}");
    }
}
