//! Compare technology and API fingerprints from completed target reports.

use crate::cli::CompareArgs;
use anyhow::Context;
use webrev_core::Scope;
use webrev_report::SessionReport;
use webrev_storage::{compare_targets, TargetFingerprint};

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
    let rendered = serde_json::to_string_pretty(&matches)?;
    match args.output {
        Some(path) => {
            std::fs::write(&path, rendered)?;
            eprintln!("comparison written to {}", path.display());
        }
        None => super::report::write_stdout(&rendered)?,
    }
    Ok(())
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
            inputs,
            output: Some(output.clone()),
        })
        .unwrap();
        let parsed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 1);
        assert_eq!(parsed[0]["shared_api_routes"][0], "GET /api/users");
    }
}
