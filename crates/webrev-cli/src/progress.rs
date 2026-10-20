// crates/webrev-cli/src/progress.rs
//! Live scan progress on **stderr** (stdout stays data-only).
//!
//! * `live`  - one in-place line (spinner, stage, counters, elapsed); chosen by
//!   `--progress auto` when stderr is an interactive terminal.
//! * `plain` - append-only timestamped lines; the `auto` choice everywhere else.
//! * `json`  - one JSON object per line, for scripts and CI.
//! * `none`  - nothing. `--quiet` forces this and mutes [`note!`] too.

use clap::ValueEnum;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use webrev_core::model::triage::terminal_text;
use webrev_pipeline::PipelineEvent;
use webrev_tui::color::{self, ColorMode};

/// `--progress` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ProgressArg {
    /// In-place line on a terminal, plain lines otherwise.
    Auto,
    /// Append-only timestamped lines.
    Plain,
    /// One JSON object per line.
    Json,
    /// No progress output.
    None,
}

/// What actually gets drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Live,
    Plain,
    Json,
    Off,
}

/// Pure resolver, parameterised so it is unit-testable.
pub fn resolve(arg: ProgressArg, quiet: bool, stderr_tty: bool, dumb: bool) -> Mode {
    if quiet {
        return Mode::Off;
    }
    match arg {
        ProgressArg::None => Mode::Off,
        ProgressArg::Plain => Mode::Plain,
        ProgressArg::Json => Mode::Json,
        ProgressArg::Auto if stderr_tty && !dumb => Mode::Live,
        ProgressArg::Auto => Mode::Plain,
    }
}

static CONFIG: OnceLock<(ProgressArg, bool)> = OnceLock::new();

/// Record `--progress` / `--quiet` once at startup.
pub fn init(arg: ProgressArg, quiet: bool) {
    let _ = CONFIG.set((arg, quiet));
}

/// `true` when `--quiet` was given.
pub fn quiet() -> bool {
    CONFIG.get().is_some_and(|c| c.1)
}

/// Informational status line on stderr, silenced by `--quiet`.
macro_rules! note {
    ($($arg:tt)*) => {
        if !$crate::progress::quiet() {
            eprintln!($($arg)*);
        }
    };
}
pub(crate) use note;

fn current_mode() -> Mode {
    let (arg, quiet) = CONFIG.get().copied().unwrap_or((ProgressArg::Auto, false));
    let dumb = std::env::var("TERM").is_ok_and(|t| t == "dumb");
    resolve(arg, quiet, std::io::stderr().is_terminal(), dumb)
}

#[derive(Default)]
struct State {
    stage: String,
    processed: usize,
    findings: usize,
    errors: usize,
    last_plain: Option<Instant>,
}

struct Inner {
    mode: Mode,
    label: String,
    start: Instant,
    color: ColorMode,
    state: Mutex<State>,
    drawn: AtomicBool,
}

const ASCII_SPINNER: [&str; 4] = ["|", "/", "-", "\\"];
const BRAILLE_SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// Minimum gap between two `Progress` heartbeat lines in plain mode.
const PLAIN_THROTTLE: Duration = Duration::from_secs(5);

impl Inner {
    fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Emit an event in `plain` / `json` mode (no-op otherwise).
    fn emit(&self, event: &str, stage: &str, message: &str, extra: serde_json::Value) {
        match self.mode {
            Mode::Plain => {
                let sep = if message.is_empty() { "" } else { ": " };
                eprintln!(
                    "[{:>7.1}s] {}: {stage}{sep}{message}",
                    self.elapsed().as_secs_f64(),
                    self.label
                );
            }
            Mode::Json => {
                let mut obj = serde_json::json!({
                    "event": event,
                    "label": self.label,
                    "stage": stage,
                    "elapsed_ms": u64::try_from(self.elapsed().as_millis()).unwrap_or(u64::MAX),
                });
                if let (Some(o), Some(e)) = (obj.as_object_mut(), extra.as_object()) {
                    o.extend(e.clone());
                }
                if !message.is_empty() {
                    obj["message"] = serde_json::Value::String(message.to_owned());
                }
                eprintln!("{obj}");
            }
            Mode::Live | Mode::Off => {}
        }
    }

    fn apply(&self, event: &PipelineEvent) {
        match event {
            PipelineEvent::StageStarted { stage } => {
                {
                    let mut st = self.state();
                    st.stage.clone_from(stage);
                    st.processed = 0;
                }
                self.emit("stage_started", stage, "started", serde_json::json!({}));
            }
            PipelineEvent::StageCompleted { stage, emitted } => {
                self.emit(
                    "stage_completed",
                    stage,
                    &format!("done, {emitted} items out"),
                    serde_json::json!({ "emitted": emitted }),
                );
            }
            PipelineEvent::Progress { stage, processed } => {
                let due = {
                    let mut st = self.state();
                    st.stage.clone_from(stage);
                    st.processed = *processed;
                    let due = self.mode == Mode::Json
                        || st.last_plain.is_none_or(|t| t.elapsed() >= PLAIN_THROTTLE);
                    if due {
                        st.last_plain = Some(Instant::now());
                    }
                    due
                };
                if due {
                    self.emit(
                        "progress",
                        stage,
                        &format!("{processed} processed"),
                        serde_json::json!({ "processed": processed }),
                    );
                }
            }
            PipelineEvent::Finding(_) => self.state().findings += 1,
            PipelineEvent::Error { stage, message } => {
                self.state().errors += 1;
                // Messages can embed target-controlled text.
                let message = terminal_text(message);
                self.emit("error", stage, &message, serde_json::json!({}));
            }
            PipelineEvent::SecretDetected { .. } => {}
        }
    }

    /// Redraw the in-place line (live mode only).
    fn draw(&self, tick: usize) {
        let st = self.state();
        let color = self.color;
        let frames: &[&str] = if color.enabled() {
            &BRAILLE_SPINNER
        } else {
            &ASCII_SPINNER
        };
        let spinner = frames[tick % frames.len()];
        let secs = self.elapsed().as_secs();
        let mut line = format!("{} · ", self.label);
        if !st.stage.is_empty() {
            line.push_str(&st.stage);
            line.push_str(" · ");
        }
        if st.processed > 0 {
            line.push_str(&format!("{} processed · ", st.processed));
        }
        line.push_str(&format!(
            "{} findings · {}:{:02}",
            st.findings,
            secs / 60,
            secs % 60
        ));
        if st.errors > 0 {
            line.push_str(&format!(" · {} errors", st.errors));
        }
        drop(st);
        let width = crate::term::width_of(std::io::stderr()).unwrap_or(80);
        let line = crate::term::fit_end(&terminal_text(&line), width.saturating_sub(3));
        let paint = match color {
            ColorMode::Truecolor => "\x1b[1;38;2;229;101;63m",
            ColorMode::Ansi256 => "\x1b[1;38;5;202m",
            ColorMode::None => "",
        };
        let reset = if paint.is_empty() { "" } else { "\x1b[0m" };
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "\r\x1b[2K{paint}{spinner}{reset} {line}");
        let _ = err.flush();
        self.drawn.store(true, Ordering::Relaxed);
    }

    fn clear(&self) {
        if self.drawn.swap(false, Ordering::Relaxed) {
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

/// A running progress display. Create with [`Progress::start`], feed it with
/// [`Progress::watch`] or [`Progress::stage`], and end it with [`Progress::finish`].
pub struct Progress {
    inner: Arc<Inner>,
    ticker: Option<JoinHandle<()>>,
    watcher: Option<JoinHandle<()>>,
}

impl Progress {
    pub fn start(label: &str) -> Self {
        Self::with_mode(label, current_mode(), color::mode(true))
    }

    fn with_mode(label: &str, mode: Mode, color: ColorMode) -> Self {
        let inner = Arc::new(Inner {
            mode,
            label: label.to_owned(),
            start: Instant::now(),
            color,
            state: Mutex::new(State::default()),
            drawn: AtomicBool::new(false),
        });
        let ticker = (mode == Mode::Live).then(|| {
            let inner = Arc::clone(&inner);
            tokio::spawn(async move {
                let mut tick = 0usize;
                loop {
                    inner.draw(tick);
                    tick = tick.wrapping_add(1);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
        });
        Self {
            inner,
            ticker,
            watcher: None,
        }
    }

    /// Consume pipeline events until the sender is dropped.
    pub fn watch(&mut self, mut events: broadcast::Receiver<PipelineEvent>) {
        if self.inner.mode == Mode::Off {
            return;
        }
        let inner = Arc::clone(&self.inner);
        self.watcher = Some(tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => inner.apply(&event),
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }));
    }

    /// Set the current stage by hand (for passes that have no event stream).
    pub fn stage(&self, name: &str) {
        {
            let mut st = self.inner.state();
            name.clone_into(&mut st.stage);
            st.processed = 0;
        }
        self.inner
            .emit("stage_started", name, "started", serde_json::json!({}));
    }

    /// Stop drawing and leave the cursor on a clean line.
    pub async fn finish(mut self) {
        if let Some(watcher) = self.watcher.take() {
            let _ = tokio::time::timeout(Duration::from_secs(1), watcher).await;
        }
        if let Some(ticker) = self.ticker.take() {
            ticker.abort();
        }
        self.inner.clear();
        let (findings, errors) = {
            let st = self.inner.state();
            (st.findings, st.errors)
        };
        self.inner.emit(
            "finished",
            "",
            "",
            serde_json::json!({ "findings": findings, "errors": errors }),
        );
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        if let Some(t) = self.ticker.take() {
            t.abort();
        }
        self.inner.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_is_live_only_on_an_interactive_terminal() {
        assert_eq!(resolve(ProgressArg::Auto, false, true, false), Mode::Live);
        assert_eq!(resolve(ProgressArg::Auto, false, false, false), Mode::Plain);
        assert_eq!(resolve(ProgressArg::Auto, false, true, true), Mode::Plain);
    }

    #[test]
    fn quiet_and_none_silence_everything() {
        assert_eq!(resolve(ProgressArg::Json, true, true, false), Mode::Off);
        assert_eq!(resolve(ProgressArg::None, false, true, false), Mode::Off);
        assert_eq!(resolve(ProgressArg::Plain, false, true, false), Mode::Plain);
        assert_eq!(resolve(ProgressArg::Json, false, false, false), Mode::Json);
    }

    #[tokio::test]
    async fn events_update_counters_without_drawing() {
        let progress = Progress::with_mode("t", Mode::Off, ColorMode::None);
        progress.inner.apply(&PipelineEvent::Error {
            stage: "fetch".into(),
            message: "boom\u{1b}[2J".into(),
        });
        progress.inner.apply(&PipelineEvent::Progress {
            stage: "fetch".into(),
            processed: 7,
        });
        let st = progress.inner.state();
        assert_eq!((st.errors, st.processed), (1, 7));
        assert_eq!(st.stage, "fetch");
    }
}
