// crates/webrev-cli/src/main.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: binary crate; anyhow carries error context, and the command
// handlers document their own behaviour. `doc_markdown` is allowed because the
// clap arg doc-comments double as `--help` text, where backticks and angle
// brackets would be noise.
#![allow(clippy::missing_errors_doc, clippy::doc_markdown)]

//! `webrev` CLI entry point.

mod cli;
mod commands;

use clap::Parser;
use cli::Command;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let parsed = cli::Cli::parse();
    // The TUI owns the terminal, so only initialise stderr logging for the
    // non-interactive subcommands.
    if !matches!(parsed.command, Command::Tui(_)) {
        init_tracing();
    }
    commands::dispatch(parsed).await
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
