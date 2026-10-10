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

// Minimal ANSI palette — kept here so the whole CLI brand lives in one place.
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";

/// Print the banner unless suppressed, the stream is redirected, or we can't.
pub fn print(suppressed: bool) {
    let mut err = std::io::stderr();
    if suppressed || !err.is_terminal() {
        return;
    }
    let color = std::env::var_os("NO_COLOR").is_none();
    let paint = |text: &str, codes: &str| {
        if color {
            format!("{codes}{text}{RESET}")
        } else {
            text.to_owned()
        }
    };

    let mark = |glyph: &str| paint(glyph, CYAN);
    let line1 = format!("  {}", mark("╭─╮"));
    let line2 = format!(
        "  {}  {}  {}",
        mark("│◠│"),
        paint("webrev", &format!("{BOLD}{CYAN}")),
        paint(&format!("v{VERSION}"), DIM),
    );
    let line3 = format!(
        "  {}  {} {} {}",
        mark("╰─╯"),
        paint(TAGLINE, DIM),
        paint("·", DIM),
        paint("authorized targets only", YELLOW),
    );

    let _ = writeln!(err, "{line1}\n{line2}\n{line3}\n");
}
