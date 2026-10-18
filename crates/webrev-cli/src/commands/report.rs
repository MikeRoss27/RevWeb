// crates/webrev-cli/src/commands/report.rs
//! `webrev report`: convert or filter an existing JSON report.

use crate::cli::{ConfidenceSel, ReportArgs, ScopeSel, SeveritySel};
use webrev_core::{Confidence, Severity};
use webrev_report::{RenderOptions, ScopeFilter, SessionReport};

fn render_options(args: &ReportArgs) -> RenderOptions {
    RenderOptions {
        format: args.format.into(),
        scope: match args.scope {
            ScopeSel::All => ScopeFilter::All,
            ScopeSel::Internal => ScopeFilter::Internal,
            ScopeSel::External => ScopeFilter::External,
        },
        min_confidence: match args.min_confidence {
            ConfidenceSel::Low => Confidence::Low,
            ConfidenceSel::Medium => Confidence::Medium,
            ConfidenceSel::High => Confidence::High,
        },
        min_severity: match args.min_severity {
            SeveritySel::Info => Severity::Info,
            SeveritySel::Low => Severity::Low,
            SeveritySel::Medium => Severity::Medium,
            SeveritySel::High => Severity::High,
            SeveritySel::Critical => Severity::Critical,
        },
        redact: !args.unredacted,
    }
}

pub fn run(args: ReportArgs) -> anyhow::Result<()> {
    use anyhow::Context;
    let body = std::fs::read(&args.input)
        .with_context(|| format!("reading JSON report {}", args.input.display()))?;
    let report: SessionReport = serde_json::from_slice(&body)
        .with_context(|| format!("parsing JSON report {}", args.input.display()))?;
    let rendered = report.render(render_options(&args))?;

    match args.output {
        Some(path) => {
            std::fs::write(&path, &rendered)?;
            // Informational: keep stdout clean for piping, so this goes to stderr.
            eprintln!("report written to {}", path.display());
        }
        // Write straight to stdout so a closed downstream pipe (e.g. `| head`)
        // ends the program cleanly instead of panicking in `println!`.
        None => write_stdout(&rendered)?,
    }
    Ok(())
}

/// Ensure a final newline without a blank JSONL row; broken pipes exit cleanly.
pub(super) fn write_stdout(body: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out.write_all(body.as_bytes()).and_then(|()| {
        out.write_all(if body.is_empty() || body.ends_with('\n') {
            b""
        } else {
            b"\n"
        })
    }) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
    }
}
