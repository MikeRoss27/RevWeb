// crates/webrev-cli/src/commands/report.rs
//! `webrev report`: export a stored session as JSON.

use crate::cli::{ConfidenceSel, Format, ReportArgs, ScopeSel, SeveritySel};
use webrev_core::{Confidence, Mission, Scope, Severity, SessionId};
use webrev_report::{RenderOptions, ReportFormat, ScopeFilter, SessionReport};
use webrev_storage::{SqliteStorage, Storage};

fn render_options(args: &ReportArgs) -> RenderOptions {
    RenderOptions {
        format: match args.format {
            Format::Json => ReportFormat::Json,
            Format::Jsonl => ReportFormat::Jsonl,
            Format::Urls => ReportFormat::Urls,
            Format::Csv => ReportFormat::Csv,
        },
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
    }
}

pub async fn run(args: ReportArgs) -> anyhow::Result<()> {
    let storage = SqliteStorage::connect(&args.db).await?;

    // Default to the most recent scan so no session id needs to be copied.
    let session = match args.session {
        Some(ref raw) => SessionId::parse(raw)?,
        None => storage.latest_session().await?.ok_or_else(|| {
            anyhow::anyhow!("no sessions found in {} — run a scan first", args.db.display())
        })?,
    };

    let findings = storage.findings_by_session(session).await?;
    let endpoints = storage.endpoints_by_session(session).await?;

    // Scope/seeds are not persisted, so the report carries minimal mission
    // metadata; the findings and endpoints are the substance.
    let mission = Mission {
        id: session,
        name: "webrev session".to_owned(),
        scope: Scope::default(),
        seeds: Vec::new(),
    };
    let rendered = SessionReport::build(mission, findings, endpoints).render(render_options(&args))?;

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

/// Write `body` + newline to stdout, treating a broken pipe as a clean exit.
fn write_stdout(body: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    match out.write_all(body.as_bytes()).and_then(|()| out.write_all(b"\n")) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(e) => Err(e.into()),
    }
}
