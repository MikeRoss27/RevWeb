// crates/webrev-cli/src/banner.rs
//! The webrev startup banner.
//!
//! The art and palette live in [`webrev_tui::brand`]; this module only maps
//! each [`Tone`] onto ANSI escapes. Printed to **stderr** (so it never
//! pollutes a `report` piped on stdout), only when stderr is a terminal, and
//! honouring `NO_COLOR`. Suppressed with the global `--no-banner` flag.

use std::io::{IsTerminal, Write};
use webrev_tui::brand::{self, Rgb, Tone};
use webrev_tui::color::{self, ColorMode};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// One-line description of the tool, reused by `--help` and the banner.
pub const TAGLINE: &str = brand::TAGLINE;

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";

fn fg(rgb: Rgb, xterm256: u8, truecolor: bool) -> String {
    if truecolor {
        format!("\x1b[38;2;{};{};{}m", rgb.0, rgb.1, rgb.2)
    } else {
        format!("\x1b[38;5;{xterm256}m")
    }
}

/// ANSI prefix for a tone.
fn escape(tone: Tone, truecolor: bool) -> String {
    match tone {
        Tone::Orange => format!("{BOLD}{}", fg(brand::ORANGE, 202, truecolor)),
        Tone::Cream => format!("{BOLD}{}", fg(brand::CREAM, 230, truecolor)),
        Tone::Dim => DIM.to_owned(),
    }
}

/// Render the banner to a string (colored or plain).
fn render(color: bool, truecolor: bool) -> String {
    let mut out = String::new();
    for row in brand::banner(TAGLINE, VERSION) {
        out.push_str("  ");
        for (tone, text) in row {
            if color {
                out.push_str(&escape(tone, truecolor));
                out.push_str(&text);
                out.push_str(RESET);
            } else {
                out.push_str(&text);
            }
        }
        out.push('\n');
    }
    out
}

/// Print the banner unless suppressed, the stream is redirected, or we can't.
pub fn print(suppressed: bool) {
    let mut err = std::io::stderr();
    if suppressed || !err.is_terminal() {
        return;
    }
    let mode = color::mode(true);
    let _ = writeln!(
        err,
        "\n{}",
        render(mode.enabled(), mode == ColorMode::Truecolor)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_banner_has_no_escape_codes() {
        let s = render(false, true);
        assert!(!s.contains('\x1b'));
        assert!(s.contains("authorized targets only"));
        assert_eq!(s.lines().count(), 8);
    }

    #[test]
    fn colored_banner_closes_every_escape() {
        let s = render(true, true);
        assert!(s.contains("\x1b[38;2;229;101;63m"), "orange truecolor");
        assert!(s.contains(RESET));
        assert!(s.trim_end().ends_with(RESET));
    }

    #[test]
    fn falls_back_to_256_colors() {
        let s = render(true, false);
        assert!(s.contains("\x1b[38;5;202m"));
        assert!(!s.contains("38;2;"));
    }
}
