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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    commands::dispatch(parsed).await
}
