// crates/webrev-tui/src/color.rs
//! One color policy for every webrev front end (banner, scan summary, TUI).
//!
//! Precedence, highest first: an explicit `--color always|never`, then the
//! environment (`NO_COLOR`, `CLICOLOR_FORCE`, `CLICOLOR`, `TERM=dumb`), then
//! whether the stream is a terminal. Following <https://no-color.org>, an
//! empty `NO_COLOR` is ignored.

use std::sync::OnceLock;

/// The user's `--color` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorChoice {
    /// Decide from the environment and whether the stream is a terminal.
    #[default]
    Auto,
    /// Always emit color, even when piped.
    Always,
    /// Never emit color.
    Never,
}

/// What a stream can display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    /// Plain text: no escapes at all.
    None,
    /// xterm-256 palette.
    Ansi256,
    /// 24-bit color.
    Truecolor,
}

impl ColorMode {
    /// `true` unless the mode is [`ColorMode::None`].
    #[must_use]
    pub fn enabled(self) -> bool {
        self != Self::None
    }
}

static CHOICE: OnceLock<ColorChoice> = OnceLock::new();

/// Record the `--color` flag once at startup; later calls are ignored.
pub fn init(choice: ColorChoice) {
    let _ = CHOICE.set(choice);
}

/// Resolve the mode for a stream using the process environment.
#[must_use]
pub fn mode(is_terminal: bool) -> ColorMode {
    resolve(
        CHOICE.get().copied().unwrap_or_default(),
        is_terminal,
        |k| std::env::var(k).ok(),
    )
}

/// Pure resolver, parameterised over the environment so it is testable.
pub fn resolve(
    choice: ColorChoice,
    is_terminal: bool,
    env: impl Fn(&str) -> Option<String>,
) -> ColorMode {
    let set = |k: &str| env(k).is_some_and(|v| !v.is_empty());
    let enabled = match choice {
        ColorChoice::Never => false,
        ColorChoice::Always => true,
        ColorChoice::Auto => {
            if set("NO_COLOR") {
                false
            } else if env("CLICOLOR_FORCE").is_some_and(|v| !v.is_empty() && v != "0") {
                true
            } else {
                env("CLICOLOR").is_none_or(|v| v != "0")
                    && is_terminal
                    && env("TERM").is_none_or(|t| t != "dumb")
            }
        }
    };
    if !enabled {
        ColorMode::None
    } else if env("COLORTERM")
        .is_some_and(|v| v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit"))
    {
        ColorMode::Truecolor
    } else {
        ColorMode::Ansi256
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    #[test]
    fn terminal_gets_color_pipe_does_not() {
        assert_eq!(
            resolve(ColorChoice::Auto, true, env(&[])),
            ColorMode::Ansi256
        );
        assert_eq!(resolve(ColorChoice::Auto, false, env(&[])), ColorMode::None);
    }

    #[test]
    fn colorterm_selects_truecolor() {
        let e = [("COLORTERM", "truecolor")];
        assert_eq!(
            resolve(ColorChoice::Auto, true, env(&e)),
            ColorMode::Truecolor
        );
    }

    #[test]
    fn no_color_wins_but_empty_is_ignored() {
        assert_eq!(
            resolve(ColorChoice::Auto, true, env(&[("NO_COLOR", "1")])),
            ColorMode::None
        );
        assert_eq!(
            resolve(ColorChoice::Auto, true, env(&[("NO_COLOR", "")])),
            ColorMode::Ansi256
        );
    }

    #[test]
    fn clicolor_variables() {
        assert_eq!(
            resolve(ColorChoice::Auto, true, env(&[("CLICOLOR", "0")])),
            ColorMode::None
        );
        assert_eq!(
            resolve(ColorChoice::Auto, false, env(&[("CLICOLOR_FORCE", "1")])),
            ColorMode::Ansi256
        );
        assert_eq!(
            resolve(ColorChoice::Auto, false, env(&[("CLICOLOR_FORCE", "0")])),
            ColorMode::None
        );
    }

    #[test]
    fn dumb_terminal_is_plain() {
        assert_eq!(
            resolve(ColorChoice::Auto, true, env(&[("TERM", "dumb")])),
            ColorMode::None
        );
    }

    #[test]
    fn explicit_flag_overrides_environment() {
        let e = [("NO_COLOR", "1")];
        assert_eq!(
            resolve(ColorChoice::Always, false, env(&e)),
            ColorMode::Ansi256
        );
        assert_eq!(
            resolve(ColorChoice::Never, true, env(&[("CLICOLOR_FORCE", "1")])),
            ColorMode::None
        );
    }
}
