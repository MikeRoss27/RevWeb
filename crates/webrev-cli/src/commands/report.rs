// crates/webrev-cli/src/commands/report.rs
//! `webrev report`: export a stored session as JSON.

use crate::cli::ReportArgs;
use webrev_core::{Mission, Scope, SessionId};
use webrev_report::SessionReport;
use webrev_storage::{SqliteStorage, Storage};

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
    let json = SessionReport::build(mission, findings, endpoints).to_json()?;

    match args.output {
        Some(path) => {
            std::fs::write(&path, &json)?;
            println!("report written to {}", path.display());
        }
        None => println!("{json}"),
    }
    Ok(())
}
