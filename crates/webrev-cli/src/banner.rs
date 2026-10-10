// crates/webrev-cli/src/banner.rs
//! The webrev startup banner.
//!
//! Printed to **stderr** (so it never pollutes a `report` piped on stdout),
//! only when stderr is a terminal, and honouring `NO_COLOR`. Suppressed with
//! the global `--no-banner` flag.

use std::io::{IsTerminal, Write};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One-line description of the tool, reused by `--help` and the TUI.
pub const TAGLINE: &str = "web reconnaissance toolkit";

// Brand palette (docs/assets) — kept here so the whole CLI brand lives in one
// place. Truecolor when the terminal advertises it, else the closest xterm-256
// entries (acid ≈ 191, bone ≈ 255).
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

struct Palette {
    acid_fg: &'static str,
    acid_bg: &'static str,
    void_fg: &'static str,
    bone_fg: &'static str,
}

const TRUECOLOR: Palette = Palette {
    acid_fg: "\x1b[38;2;198;255;61m",
    acid_bg: "\x1b[48;2;198;255;61m",
    void_fg: "\x1b[38;2;10;10;10m",
    bone_fg: "\x1b[38;2;237;237;230m",
};

const XTERM_256: Palette = Palette {
    acid_fg: "\x1b[38;5;191m",
    acid_bg: "\x1b[48;5;191m",
    void_fg: "\x1b[38;5;232m",
    bone_fg: "\x1b[38;5;255m",
};

/// Print the banner unless suppressed, the stream is redirected, or we can't.
pub fn print(suppressed: bool) {
    let mut err = std::io::stderr();
    if suppressed || !err.is_terminal() {
        return;
    }
    let color = std::env::var_os("NO_COLOR").is_none();
    let truecolor = std::env::var("COLORTERM")
        .is_ok_and(|v| v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit"));
    let p = if truecolor { &TRUECOLOR } else { &XTERM_256 };
    let paint = |text: &str, codes: &str| {
        if color {
            format!("{codes}{text}{RESET}")
        } else {
            text.to_owned()
        }
    };

    // The mark: `<_` reversed out of an acid badge.
    let badge = paint(" <_ ", &format!("{BOLD}{}{}", p.acid_bg, p.void_fg));
    let line1 = format!(
        "  {badge}  {} {}",
        paint("webrev", &format!("{BOLD}{}", p.bone_fg)),
        paint(VERSION, DIM),
    );
    let line2 = format!(
        "        {} {} {}",
        paint(TAGLINE, DIM),
        paint("·", DIM),
        paint("authorized targets only", p.acid_fg),
    );

    let _ = writeln!(err, "\n{line1}\n{line2}\n");
}
