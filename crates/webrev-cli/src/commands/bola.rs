//! Read-only BOLA checks from two account-specific dynamic scan reports.

use crate::cli::BolaArgs;
use anyhow::Context;
use tokio_util::sync::CancellationToken;
use webrev_core::{ActiveLimits, AuthConfig, EgressPolicy, Mission, OpsecConfig, Scope};
use webrev_pipeline::{active_targets, bola_candidates, run_bola_scan, BolaCandidate};
use webrev_report::SessionReport;
use webrev_storage::{InMemoryStorage, Storage};

pub async fn run(args: BolaArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.max_requests >= 4,
        "--max-requests must allow at least four control requests"
    );
    let auth_a = read_auth(&args.a_auth)?;
    let auth_b = read_auth(&args.b_auth)?;
    let mut opsec = OpsecConfig {
        auth: auth_a.clone(),
        active: ActiveLimits {
            max_requests: args.max_requests,
            ..ActiveLimits::default()
        },
        egress: EgressPolicy {
            proxy: args.proxy.clone(),
            ..EgressPolicy::default()
        },
        ..OpsecConfig::default()
    };
    let (a, b) = match (&args.a_report, &args.b_report, args.seeds.is_empty()) {
        (Some(a_path), Some(b_path), true) if args.scope.is_empty() => {
            (read_report(a_path)?, read_report(b_path)?)
        }
        (None, None, false) => {
            let a = capture_account(&args.seeds, &args.scope, &opsec, args.duration_secs).await?;
            opsec.auth = auth_b.clone();
            let b = capture_account(&args.seeds, &args.scope, &opsec, args.duration_secs).await?;
            opsec.auth = auth_a.clone();
            (a, b)
        }
        _ => anyhow::bail!("provide --seed (repeatable, optionally with --scope) or both --a-report and --b-report"),
    };
    let targets_a = active_targets(&a.mission, &a.findings);
    let targets_b = active_targets(&b.mission, &b.findings);
    let candidates: Vec<_> = bola_candidates(&targets_a, &targets_b)
        .into_iter()
        .filter(|candidate| {
            b.mission.scope.allows(&candidate.account_a_url)
                && b.mission.scope.allows(&candidate.account_b_url)
        })
        .collect();
    let (candidates, skipped) = without_masked_urls(candidates);
    if skipped > 0 {
        eprintln!(
            "BOLA: skipped {skipped} pair(s) whose captured URL had a credential masked; \
             capture them again without --redact (or WEBREV_REPORT_REDACT) to compare them"
        );
    }
    eprintln!(
        "BOLA: {} captured object pair(s) eligible for read-only comparison",
        candidates.len()
    );

    let cancel = CancellationToken::new();
    let scan = run_bola_scan(
        &opsec,
        &a.mission.scope,
        a.mission.id,
        &auth_a,
        &auth_b,
        &candidates,
        cancel.clone(),
    );
    tokio::pin!(scan);
    let findings = tokio::select! {
        result = &mut scan => result?,
        signal = tokio::signal::ctrl_c() => {
            if signal.is_ok() {
                cancel.cancel();
                eprintln!("BOLA scan interrupted; writing available findings and coverage");
            }
            scan.await?
        }
    };
    let signals = findings
        .iter()
        .filter(|f| f.kind == webrev_core::FindingKind::Idor)
        .count();
    let report = SessionReport::build(a.mission.clone(), findings, Vec::new());
    let rendered = report.export_json(args.redact)?;
    if args.output == std::path::Path::new("-") {
        super::report::write_stdout(&rendered)?;
    } else {
        std::fs::write(&args.output, rendered)
            .with_context(|| format!("writing BOLA report {}", args.output.display()))?;
        eprintln!(
            "BOLA: {signals} signal(s); report written to {}",
            args.output.display()
        );
        super::warn_if_raw(args.redact);
    }
    Ok(())
}

pub(crate) async fn capture_account(
    seeds: &[String],
    scope: &[String],
    opsec: &OpsecConfig,
    duration_secs: u64,
) -> anyhow::Result<SessionReport> {
    let mut hosts = Vec::new();
    for seed in seeds {
        let url = reqwest::Url::parse(seed).with_context(|| {
            format!("invalid BOLA seed URL {:?}", webrev_core::redact_url(seed))
        })?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https"),
            "BOLA seeds must use HTTP(S)"
        );
        anyhow::ensure!(
            url.username().is_empty() && url.password().is_none(),
            "BOLA seeds must not contain URL credentials"
        );
        hosts.push(url.host_str().context("BOLA seed missing host")?.to_owned());
    }
    hosts.sort();
    hosts.dedup();
    let include = if scope.is_empty() {
        hosts
    } else {
        super::normalize_scope_hosts(scope)?
    };
    let boundary = Scope::new(include, Vec::new());
    anyhow::ensure!(
        seeds.iter().all(|seed| boundary.allows(seed)),
        "every BOLA seed must be inside --scope"
    );
    let mission = Mission::new("bola-capture", boundary, seeds.to_vec());
    let storage = InMemoryStorage::new();
    storage.create_session(&mission).await?;
    let cancel = CancellationToken::new();
    super::dynamic_scan::run_pass(opsec, &mission, duration_secs, &cancel, &storage).await?;
    Ok(SessionReport::build(
        mission.clone(),
        storage.findings_by_session(mission.id).await?,
        storage.endpoints_by_session(mission.id).await?,
    ))
}

/// Object ids survive masking, but a credential in a captured URL does not: a
/// pair whose URL now says `[REDACTED]` cannot be replayed as it was seen.
/// Returns the replayable pairs and how many were dropped.
fn without_masked_urls(candidates: Vec<BolaCandidate>) -> (Vec<BolaCandidate>, usize) {
    let total = candidates.len();
    let replayable: Vec<_> = candidates
        .into_iter()
        .filter(|candidate| {
            !(candidate.account_a_url.contains("REDACTED")
                || candidate.account_b_url.contains("REDACTED"))
        })
        .collect();
    let skipped = total - replayable.len();
    (replayable, skipped)
}

pub(crate) fn read_report(path: &std::path::Path) -> anyhow::Result<SessionReport> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading report {}", path.display()))?;
    let report: SessionReport = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing report {}", path.display()))?;
    Ok(report)
}

pub(crate) fn read_auth(path: &std::path::Path) -> anyhow::Result<AuthConfig> {
    let bytes =
        std::fs::read(path).with_context(|| format!("reading auth file {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing auth file {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn report_mode_writes_coverage_without_network_when_no_pairs_exist() {
        let directory = tempfile::tempdir().unwrap();
        let mission = Mission::new(
            "test",
            Scope::new(vec!["example.test".into()], vec![]),
            vec!["https://example.test/".into()],
        );
        let input = SessionReport::build(mission, Vec::new(), Vec::new())
            .to_json()
            .unwrap();
        let a_report = directory.path().join("a-report.json");
        let b_report = directory.path().join("b-report.json");
        std::fs::write(&a_report, &input).unwrap();
        std::fs::write(&b_report, &input).unwrap();
        let a_auth = directory.path().join("a-auth.json");
        let b_auth = directory.path().join("b-auth.json");
        std::fs::write(&a_auth, r#"{"bearer":"account-a"}"#).unwrap();
        std::fs::write(&b_auth, r#"{"bearer":"account-b"}"#).unwrap();
        let output = directory.path().join("result.json");
        run(BolaArgs {
            a_report: Some(a_report),
            b_report: Some(b_report),
            seeds: Vec::new(),
            scope: Vec::new(),
            a_auth,
            b_auth,
            output: output.clone(),
            max_requests: 4,
            proxy: None,
            duration_secs: 0,
            redact: false,
        })
        .await
        .unwrap();
        let result: SessionReport =
            serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].coverage.is_some());
    }

    #[test]
    fn masked_reports_are_read_and_keep_their_marker() {
        let directory = tempfile::tempdir().unwrap();
        let mission = Mission::new(
            "test",
            Scope::new(vec!["example.test".into()], vec![]),
            vec!["https://example.test/".into()],
        );
        let report = SessionReport::build(mission, Vec::new(), Vec::new());
        let masked = directory.path().join("masked.json");
        std::fs::write(&masked, report.export_json(true).unwrap()).unwrap();
        let raw = directory.path().join("raw.json");
        std::fs::write(&raw, report.export_json(false).unwrap()).unwrap();

        assert!(read_report(&masked).unwrap().redacted);
        assert!(!read_report(&raw).unwrap().redacted);
    }

    #[test]
    fn pairs_with_a_masked_credential_are_skipped_but_object_ids_are_kept() {
        let id = "550e8400-e29b-41d4-a716-446655440001";
        let pair = |a: String, b: String| BolaCandidate {
            route: "/api/orders/{uuid}".into(),
            account_a_url: a,
            account_b_url: b,
        };
        let (kept, skipped) = without_masked_urls(vec![
            pair(
                format!("https://x.test/api/orders/{id}"),
                "https://x.test/api/orders/550e8400-e29b-41d4-a716-446655440002".into(),
            ),
            pair(
                format!("https://x.test/api/orders/{id}?token=[REDACTED]"),
                "https://x.test/api/orders/550e8400-e29b-41d4-a716-446655440002".into(),
            ),
        ]);
        assert_eq!((kept.len(), skipped), (1, 1));
        assert!(kept[0].account_a_url.ends_with(id));
    }
}
