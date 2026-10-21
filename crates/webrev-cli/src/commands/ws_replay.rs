//! Replay / bounded-mutation CLI for captured WebSocket frames. Mirrors
//! `bola.rs`'s report-or-live-capture shape; see
//! `webrev_pipeline::active::ws_replay` for the actual probe and its
//! guardrails (scope, destructive-content refusal, frame budget).

use super::bola::{capture_account, read_auth, read_report};
use crate::cli::WsReplayArgs;
use anyhow::Context;
use tokio_util::sync::CancellationToken;
use webrev_core::{ActiveLimits, AuthConfig, EgressPolicy, OpsecConfig};
use webrev_pipeline::{run_ws_replay_scan, ws_frame_candidates, WsMutation};
use webrev_report::SessionReport;

pub async fn run(args: WsReplayArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        args.mutate_find.is_none() || args.b_auth.is_some() || args.mutate_replace.is_some(),
        "--mutate-find without --b-auth replays the mutated frame but has nothing to compare it \
         against; pass --b-auth for a cross-account signal, or drop --mutate-find for a plain \
         reproducibility replay"
    );
    let auth_a = read_auth(&args.auth)?;
    let auth_b = args.b_auth.as_deref().map(read_auth).transpose()?;
    anyhow::ensure!(
        distinct_accounts(&auth_a, auth_b.as_ref()),
        "--b-auth must be a distinct account profile from --auth, or every cross-account \
         comparison is vacuous"
    );
    let opsec = OpsecConfig {
        auth: auth_a.clone(),
        active: ActiveLimits {
            max_requests: args.max_requests,
            ..ActiveLimits::default()
        },
        // ws_replay refuses outright when a proxy is configured (see its
        // module docs): the egress policy here stays direct-only.
        egress: EgressPolicy::default(),
        ..OpsecConfig::default()
    };
    let report = match (&args.report, args.seeds.is_empty()) {
        (Some(path), true) if args.scope.is_empty() => read_report(path)?,
        (None, false) => {
            capture_account(&args.seeds, &args.scope, &opsec, args.duration_secs).await?
        }
        _ => anyhow::bail!("provide --seed (repeatable, optionally with --scope) or --report"),
    };
    let candidates: Vec<_> = ws_frame_candidates(&report.findings)
        .into_iter()
        .filter(|c| report.mission.scope.allows(&c.socket_url))
        .collect();
    eprintln!(
        "ws-replay: {} captured `Sent` frame(s) eligible for replay",
        candidates
            .iter()
            .filter(|c| c.direction == webrev_pipeline::WsDirection::Sent)
            .count()
    );
    let mutation = match (&args.mutate_find, &args.mutate_replace) {
        (Some(find), Some(replace)) => Some(WsMutation {
            find: find.clone(),
            replace: replace.clone(),
        }),
        _ => None,
    };

    let cancel = CancellationToken::new();
    let scan = run_ws_replay_scan(
        &opsec,
        &report.mission.scope,
        report.mission.id,
        &auth_a,
        auth_b.as_ref(),
        &candidates,
        mutation.as_ref(),
        cancel.clone(),
    );
    tokio::pin!(scan);
    let findings = tokio::select! {
        result = &mut scan => result?,
        signal = tokio::signal::ctrl_c() => {
            if signal.is_ok() {
                cancel.cancel();
                eprintln!("ws-replay interrupted; writing available findings and coverage");
            }
            scan.await?
        }
    };
    let signals = findings
        .iter()
        .filter(|f| f.kind == webrev_core::FindingKind::Idor)
        .count();
    let replayed = findings
        .iter()
        .filter(|f| f.kind == webrev_core::FindingKind::WebSocketReplay)
        .count();
    let result = SessionReport::build(report.mission.clone(), findings, Vec::new());
    let rendered = result.export_json(args.redact)?;
    if args.output == std::path::Path::new("-") {
        super::report::write_stdout(&rendered)?;
    } else {
        std::fs::write(&args.output, rendered)
            .with_context(|| format!("writing ws-replay report {}", args.output.display()))?;
        eprintln!(
            "ws-replay: {replayed} frame(s) replayed, {signals} cross-account signal(s); report \
             written to {}",
            args.output.display()
        );
        super::warn_if_raw(args.redact);
    }
    Ok(())
}

/// Not used directly (kept for parity with `bola::validate_account`'s intent,
/// inlined here since ws_replay accepts a lone account too): both account
/// configs, when both are given, must actually differ, or a cross-account
/// comparison is vacuous.
#[allow(dead_code)]
fn distinct_accounts(a: &AuthConfig, b: Option<&AuthConfig>) -> bool {
    b.is_none_or(|b| a != b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::{Mission, Scope};

    #[tokio::test]
    async fn report_mode_writes_coverage_without_network_when_no_frames_exist() {
        let directory = tempfile::tempdir().unwrap();
        let mission = Mission::new(
            "test",
            Scope::new(vec!["example.test".into()], vec![]),
            vec!["https://example.test/".into()],
        );
        let input = SessionReport::build(mission, Vec::new(), Vec::new())
            .to_json()
            .unwrap();
        let report_path = directory.path().join("report.json");
        std::fs::write(&report_path, &input).unwrap();
        let auth_path = directory.path().join("auth.json");
        std::fs::write(&auth_path, r#"{"bearer":"account-a"}"#).unwrap();
        let output = directory.path().join("result.json");
        run(WsReplayArgs {
            report: Some(report_path),
            seeds: Vec::new(),
            scope: Vec::new(),
            auth: auth_path,
            b_auth: None,
            mutate_find: None,
            mutate_replace: None,
            output: output.clone(),
            max_requests: 10,
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
    fn distinct_accounts_requires_an_actual_difference() {
        let a = AuthConfig {
            bearer: Some("x".into()),
            ..AuthConfig::default()
        };
        assert!(distinct_accounts(&a, None));
        assert!(!distinct_accounts(&a, Some(&a)));
    }
}
