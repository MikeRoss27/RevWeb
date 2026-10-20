// crates/webrev-cli/src/main.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: binary crate; anyhow carries error context, and the command
// handlers document their own behaviour. `doc_markdown` is allowed because the
// clap arg doc-comments double as `--help` text, where backticks and angle
// brackets would be noise.
#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]

//! `webrev` CLI entry point.

mod banner;
mod cli;
mod commands;
mod logging;
mod progress;
mod term;

use clap::Parser;
use cli::Command;

/// Exit status: 0 success, 1 runtime failure, 2 usage error (clap and
/// [`commands::UsageError`]), 3 `--fail-on` threshold reached.
const EXIT_RUNTIME: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_FINDINGS: u8 = 3;

/// A fix-it hint for common runtime failures.
fn hint_for(error: &anyhow::Error) -> Option<&'static str> {
    if let Some(usage) = error.downcast_ref::<commands::UsageError>() {
        return usage.hint;
    }
    let text = format!("{error:#}").to_ascii_lowercase();
    if text.contains("reading json report") {
        return Some("run a scan first, or point --input at an existing report");
    }
    if text.contains("chrom") {
        return Some("dynamic analysis needs Chrome or Chromium installed and launchable");
    }
    None
}

fn exit_code_and_print(error: &anyhow::Error) -> u8 {
    use std::io::IsTerminal;
    let findings = error.downcast_ref::<commands::FindingsFailure>().is_some();
    let mode = webrev_tui::color::mode(std::io::stderr().is_terminal());
    let (red, reset) = if mode.enabled() {
        ("\x1b[1;31m", "\x1b[0m")
    } else {
        ("", "")
    };
    let label = if findings { "findings" } else { "error" };
    eprintln!("{red}{label}:{reset} {error:#}");
    if let Some(hint) = hint_for(error) {
        eprintln!("hint: {hint}");
    }
    if findings {
        EXIT_FINDINGS
    } else if error.downcast_ref::<commands::UsageError>().is_some() {
        EXIT_USAGE
    } else {
        EXIT_RUNTIME
    }
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Bare `webrev` and any `--help` are answered by clap before `parse`
    // returns, so brand them up front (still stderr-only, tty-only).
    let args: Vec<String> = std::env::args().skip(1).collect();
    let asks_for_help = args.is_empty()
        || args.first().is_some_and(|a| a == "help")
        || args.iter().any(|a| a == "-h" || a == "--help");
    if asks_for_help {
        banner::print(
            args.iter()
                .any(|a| a == "--no-banner" || a == "-q" || a == "--quiet"),
        );
    }

    let parsed = cli::Cli::parse();
    webrev_tui::color::init(parsed.color.into());
    progress::init(parsed.progress, parsed.quiet);
    // Brand every non-interactive command that works on a target; keep
    // `report` silent so its stdout stays pipe-clean, and let the TUI show its
    // own branded header. The banner itself skips non-TTY stderr and --quiet.
    if matches!(
        parsed.command,
        Command::Scan(_)
            | Command::Static(_)
            | Command::Dynamic(_)
            | Command::Active(_)
            | Command::Bola(_)
            | Command::Compare(_)
    ) {
        banner::print(parsed.no_banner || parsed.quiet);
    }
    // The TUI owns the terminal, so only initialise stderr logging for the
    // non-interactive subcommands.
    if !matches!(parsed.command, Command::Tui(_)) {
        logging::init();
    }
    match commands::dispatch(parsed).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => std::process::ExitCode::from(exit_code_and_print(&error)),
    }
}
