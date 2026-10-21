//! Compare technology, API route, and secret fingerprints from completed
//! target reports to spot infrastructure reuse across a multi-target
//! engagement. See `webrev_storage::fingerprint` for how the signals are
//! weighted; a match is a lead for manual investigation, not proof.

use crate::cli::{CompareArgs, CompareFormat};
use anyhow::Context;
use std::fmt::Write as _;
use webrev_core::Scope;
use webrev_report::SessionReport;
use webrev_storage::{compare_targets, TargetFingerprint, TargetMatch};

pub fn run(args: CompareArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.inputs.len() >= 2,
        "compare requires at least two --input reports"
    );
    let mut fingerprints = Vec::with_capacity(args.inputs.len());
    for path in &args.inputs {
        let body = std::fs::read(path)
            .with_context(|| format!("reading JSON report {}", path.display()))?;
        let report: SessionReport = serde_json::from_slice(&body)
            .with_context(|| format!("parsing JSON report {}", path.display()))?;
        let target = report
            .mission
            .seeds
            .iter()
            .find_map(|seed| Scope::host_of(seed))
            .or_else(|| report.mission.scope.include.first().map(String::as_str))
            .with_context(|| format!("report {} has no target host", path.display()))?;
        fingerprints.push(TargetFingerprint::from_scan(
            target,
            &report.findings,
            &report.endpoints,
        ));
    }

    let matches = compare_targets(&fingerprints);
    let rendered = match args.format {
        CompareFormat::Json => serde_json::to_string_pretty(&matches)?,
        CompareFormat::Text => render_text(&matches),
    };
    match args.output {
        Some(path) => {
            std::fs::write(&path, rendered)?;
            eprintln!("comparison written to {}", path.display());
        }
        None => super::report::write_stdout(&rendered)?,
    }
    Ok(())
}

/// One triage line per matched pair, tier first (the honest qualifier),
/// score second (only meaningful to rank matches sharing a tier).
fn render_text(matches: &[TargetMatch]) -> String {
    if matches.is_empty() {
        return "no shared infrastructure signal across the given targets".to_owned();
    }
    let mut out = String::new();
    for m in matches {
        let _ = writeln!(
            out,
            "[{}] {} <-> {} (score {})",
            m.tier.to_string().to_ascii_uppercase(),
            m.left,
            m.right,
            m.score
        );
        if !m.shared_secrets.is_empty() {
            let _ = writeln!(out, "    shared secrets: {}", m.shared_secrets.join(", "));
        }
        if !m.shared_api_routes.is_empty() {
            let _ = writeln!(
                out,
                "    shared api routes: {}",
                m.shared_api_routes.join(", ")
            );
        }
        if !m.shared_technologies.is_empty() {
            let _ = writeln!(
                out,
                "    shared technologies: {}",
                m.shared_technologies.join(", ")
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{
        Confidence, Endpoint, Finding, FindingKind, Method, Mission, Provenance, Scope, Source,
    };

    #[test]
    fn compares_two_report_files() {
        let directory = tempfile::tempdir().unwrap();
        let mut inputs = Vec::new();
        for host in ["a.test", "b.test"] {
            let mission = Mission::new(
                host,
                Scope::new(vec![host.to_owned()], vec![]),
                vec![format!("https://{host}/")],
            );
            let finding = Finding::new(
                mission.id,
                FindingKind::Technology,
                Some(format!("https://{host}/")),
                "Next.js",
                Confidence::High,
                Provenance::new(Source::Html, None),
            );
            let endpoint = Endpoint::new(
                format!("https://{host}/api/users"),
                Method::Get,
                Source::JsAst,
            );
            let report = SessionReport::build(mission, vec![finding], vec![endpoint]);
            let input = directory.path().join(format!("{host}.json"));
            std::fs::write(&input, report.to_json().unwrap()).unwrap();
            inputs.push(input);
        }
        let output = directory.path().join("comparison.json");
        run(CompareArgs {
            inputs: inputs.clone(),
            output: Some(output.clone()),
            format: CompareFormat::Json,
        })
        .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 1);
        assert_eq!(parsed[0]["shared_api_routes"][0], "GET /api/users");
        // Both sides saw the route in static JS (confidence >= `static`), so
        // this clears the bar for `moderate`, not just a weak tech overlap.
        assert_eq!(parsed[0]["tier"], "moderate");

        let text_output = directory.path().join("comparison.txt");
        run(CompareArgs {
            inputs,
            output: Some(text_output.clone()),
            format: CompareFormat::Text,
        })
        .unwrap();
        let text = std::fs::read_to_string(text_output).unwrap();
        assert!(text.contains("[MODERATE]"));
        assert!(text.contains("shared api routes: GET /api/users"));
    }

    #[test]
    fn no_overlap_reports_no_signal_in_text_mode() {
        let directory = tempfile::tempdir().unwrap();
        let mut inputs = Vec::new();
        for (host, tech) in [("a.test", "Django"), ("b.test", "Rails")] {
            let mission = Mission::new(
                host,
                Scope::new(vec![host.to_owned()], vec![]),
                vec![format!("https://{host}/")],
            );
            let finding = Finding::new(
                mission.id,
                FindingKind::Technology,
                Some(format!("https://{host}/")),
                tech,
                Confidence::High,
                Provenance::new(Source::Html, None),
            );
            let report = SessionReport::build(mission, vec![finding], vec![]);
            let input = directory.path().join(format!("{host}.json"));
            std::fs::write(&input, report.to_json().unwrap()).unwrap();
            inputs.push(input);
        }
        let output = directory.path().join("comparison.txt");
        run(CompareArgs {
            inputs,
            output: Some(output.clone()),
            format: CompareFormat::Text,
        })
        .unwrap();
        let text = std::fs::read_to_string(output).unwrap();
        assert_eq!(
            text,
            "no shared infrastructure signal across the given targets"
        );
    }
}
