//! Wire-level regression fixtures: positives, controls and incomplete scans.
mod bola;
mod fixture;
mod limits;
mod proofs;
mod recon;
mod safety;

use super::*;
use fixture::{Fixture, Reply};
use webrev_core::{ActiveLimits, AuthConfig};

fn config() -> OpsecConfig {
    OpsecConfig {
        delay_min_ms: 0,
        delay_max_ms: 0,
        ..OpsecConfig::default()
    }
}

fn coverage(findings: &[Finding]) -> &webrev_core::ActiveCoverage {
    findings
        .iter()
        .find_map(|f| f.coverage.as_ref())
        .expect("coverage recorded")
}

async fn scan(fixture: &Fixture, paths: &[&str], opsec: &OpsecConfig) -> Vec<Finding> {
    let endpoints: Vec<_> = paths
        .iter()
        .map(|path| {
            Endpoint::new(
                format!("{}{path}", fixture.origin),
                Method::Get,
                Source::Html,
            )
        })
        .collect();
    run_active_scan(
        opsec,
        &Scope::new(vec!["127.0.0.1".into()], vec![]),
        SessionId::new(),
        &endpoints,
        CancellationToken::new(),
    )
    .await
    .unwrap()
}
