//! Scan session state: spinner clock, progress line, toasts, quit/export flow.

use super::App;
use std::time::{Duration, Instant};
use webrev_core::model::triage::terminal_text;

/// How long a toast stays on screen.
pub const TOAST_TTL: Duration = Duration::from_secs(3);

const BRAILLE: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const ASCII: [&str; 4] = ["|", "/", "-", "\\"];

/// Latest heartbeat of the running scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanProgress {
    /// Pipeline stage name, already sanitized for display.
    pub stage: String,
    pub processed: usize,
}

/// A short-lived notification.
#[derive(Debug, Clone)]
pub struct Toast {
    pub text: String,
    pub(crate) expires: Instant,
}

/// Result of a background report export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportOutcome {
    /// Written; carries the user-facing message.
    Written(String),
    /// The target file exists and overwriting was not confirmed.
    Exists(String),
    Failed(String),
}

impl App {
    /// Mark a scan as running (idempotent) and start its clock.
    pub fn begin_scan(&mut self) {
        if !self.scanning {
            self.scanning = true;
            self.scan_started = Some(Instant::now());
            self.elapsed_secs = 0;
        }
    }

    /// Mark the scan as finished and drop its progress line.
    pub(super) fn end_scan(&mut self) {
        self.scanning = false;
        self.scan_started = None;
        self.progress = None;
        self.scans_completed += 1;
    }

    /// Advance time-driven state. Returns `true` when the next frame differs
    /// from the last one (spinner moved, elapsed second changed, toast expired),
    /// so the caller can skip idle redraws.
    pub fn tick(&mut self, now: Instant) -> bool {
        let mut changed = false;
        if self.scanning {
            self.tick_count = self.tick_count.wrapping_add(1);
            if let Some(started) = self.scan_started {
                self.elapsed_secs = now.saturating_duration_since(started).as_secs();
            }
            changed = true;
        }
        if self.toast.as_ref().is_some_and(|t| now >= t.expires) {
            self.toast = None;
            changed = true;
        }
        changed
    }

    /// Show a toast for `TOAST_TTL`. Text is sanitized: it may derive from the target.
    pub fn show_toast(&mut self, text: &str) {
        self.toast = Some(Toast {
            text: terminal_text(text),
            expires: Instant::now() + TOAST_TTL,
        });
    }

    /// Current spinner glyph (ASCII fallback when Unicode/color is unavailable).
    #[must_use]
    pub fn spinner(&self) -> &'static str {
        let frames: &[&str] = if self.spinner_ascii { &ASCII } else { &BRAILLE };
        let idx = usize::try_from(self.tick_count % frames.len() as u64).unwrap_or(0);
        frames[idx]
    }

    /// Footer progress text such as `static · 128 processed · 12s`.
    #[must_use]
    pub fn progress_line(&self) -> String {
        let secs = self.elapsed_secs;
        let time = if secs >= 60 {
            format!("{}m{:02}s", secs / 60, secs % 60)
        } else {
            format!("{secs}s")
        };
        match &self.progress {
            Some(p) => format!("{} · {} processed · {time}", p.stage, p.processed),
            None => format!("starting · {time}"),
        }
    }

    /// Ask to leave: straight out when nothing would be lost, else confirm.
    pub fn request_quit(&mut self) {
        if self.scanning || self.dirty {
            self.confirm_quit = true;
        } else {
            self.should_quit = true;
        }
    }

    /// Esc: close the innermost open layer; quit (with confirmation) from the bare list.
    pub fn back(&mut self) {
        if self.show_help {
            self.show_help = false;
        } else if self.show_detail {
            self.show_detail = false;
        } else if !self.filter.is_empty() {
            self.filter_cancel();
        } else {
            self.request_quit();
        }
    }

    pub(super) fn apply_export(&mut self, outcome: ExportOutcome) {
        match outcome {
            ExportOutcome::Written(msg) => {
                self.dirty = false;
                self.report_written = true;
                self.push_status(&msg);
                self.show_toast(&msg);
                if self.quit_after_export {
                    self.should_quit = true;
                }
            }
            ExportOutcome::Exists(path) => {
                self.quit_after_export = false;
                self.confirm_quit = false;
                self.overwrite_pending = true;
                let msg =
                    format!("{path} exists: press r again to overwrite, any other key cancels");
                self.push_status(&msg);
                self.show_toast(&msg);
            }
            ExportOutcome::Failed(err) => {
                self.quit_after_export = false;
                let msg = format!("report failed: {err}");
                self.push_status(&msg);
                self.show_toast(&msg);
            }
        }
    }

    fn push_status(&mut self, msg: &str) {
        self.push_log(&format!("[status] {msg}"));
        msg.clone_into(&mut self.status);
    }
}
