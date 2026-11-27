//! Wire-level fixtures for the opt-in timing-injection probe.
use super::{
    fixture::{path, query},
    *,
};

fn timing_config() -> OpsecConfig {
    OpsecConfig {
        active: ActiveLimits {
            allow_timing_probes: true,
            ..ActiveLimits::default()
        },
        ..config()
    }
}

/// Parse the delay the probe injected, as a real vulnerable backend would
/// read it out of a shell command before executing it — this test never
/// actually spawns a shell; it only decides how long the fixture itself
/// should wait, to simulate the effect of that command having run.
fn injected_delay_secs(value: &str) -> u64 {
    if let Some(rest) = value.split(";sleep ").nth(1) {
        rest.split(';')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0)
    } else if let Some(rest) = value.split("|ping -n ").nth(1) {
        let count: u64 = rest
            .split(' ')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(1);
        count.saturating_sub(1)
    } else {
        0
    }
}

#[tokio::test]
async fn timing_signal_requires_two_scaled_delays_and_is_never_confirmed() {
    let fixture = Fixture::new(|request| {
        let value = query(request)
            .first()
            .map_or(String::new(), |(_, v)| v.clone());
        Reply {
            delay_ms: injected_delay_secs(&value) * 1000,
            ..Reply::html("ok")
        }
    });
    let findings = scan(&fixture, &["/run?cmd=ping"], &timing_config()).await;
    let rce = findings.iter().find(|f| f.category() == "RCE").unwrap();
    let proof = rce.evidence.as_ref().unwrap();
    assert_eq!(
        proof.verdict,
        webrev_core::EvidenceVerdict::TimingCorrelated
    );
    assert_eq!(proof.observations.len(), 3);
    assert_eq!(rce.status, webrev_core::FindingStatus::Suspicious);
    assert!(rce.assessment().contains("not certain"));
}

#[tokio::test]
async fn an_inert_endpoint_never_produces_a_timing_finding() {
    // Does not interpret the payload at all: every response is immediate.
    let fixture = Fixture::new(|_| Reply::html("ok"));
    let findings = scan(&fixture, &["/search?q=hello"], &timing_config()).await;
    assert!(!findings.iter().any(|f| f.category() == "RCE"));
}

#[tokio::test]
async fn timing_probe_is_disabled_unless_explicitly_allowed() {
    let fixture = Fixture::new(|request| {
        let value = query(request)
            .first()
            .map_or(String::new(), |(_, v)| v.clone());
        Reply {
            delay_ms: injected_delay_secs(&value) * 1000,
            ..Reply::html("ok")
        }
    });
    // Default config: allow_timing_probes is false.
    let findings = scan(&fixture, &["/run?cmd=hello"], &config()).await;
    assert!(!findings.iter().any(|f| f.category() == "RCE"));
    assert!(coverage(&findings).checks["timing_injection"].not_selected > 0);
    assert_eq!(coverage(&findings).checks["timing_injection"].executed, 0);
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| !path(r).contains("sleep") && !path(r).contains("ping")));
}

#[tokio::test]
async fn a_uniformly_slow_endpoint_is_not_mistaken_for_injection() {
    // Every response (payload and control alike) is equally slow; the net
    // delay after subtracting the control must stay below threshold.
    let fixture = Fixture::new(|_| Reply {
        delay_ms: 300,
        ..Reply::html("ok")
    });
    let findings = scan(&fixture, &["/slow?q=hello"], &timing_config()).await;
    assert!(!findings.iter().any(|f| f.category() == "RCE"));
}
