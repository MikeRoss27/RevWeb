//! Opt-in, timing-based blind command-injection probe.
//!
//! Every other active probe is GET-shaped and, per `docs/security.md`
//! ("Probe behavior"), never executes OS commands, writes files or triggers
//! callbacks. This check is the one documented exception: it injects a
//! `sleep`-shaped command separator and measures whether the response is
//! delayed by roughly the injected amount, which — if the target is
//! vulnerable — means a real shell command actually ran and slept. No file
//! write, no callback, no destructive verb. Disabled unless the operator
//! passes `--allow-timing-probes` (`OpsecConfig.active.allow_timing_probes`).
//!
//! A single slow response proves nothing: a slow endpoint, network jitter or
//! rate limiting can look identical to an injected delay. To rule that out,
//! each candidate is tested at two distinct injected delays, each measured
//! against a length-matched, non-executing control carrying the same number
//! (so parsing/transport overhead from the longer value cancels out). Both
//! magnitudes must show a net delay close to what was injected, and the
//! larger injected delay must produce the larger net delay. Even then, this
//! stays at `EvidenceVerdict::TimingCorrelated`, never `Confirmed`: timing is
//! a side channel, not a deterministic proof.
use super::{
    client::vuln_finding, evidence::attach, transport::ProbeClient, urls::mutate_parameter,
};
use std::time::{Duration, Instant};
use webrev_core::{Confidence, EvidenceVerdict, Finding, ResponseObservation, SessionId};

/// First injected delay, in seconds. Chosen well clear of ordinary network
/// jitter and comfortably inside the probe client's request timeout.
const DELAY_1_SECS: u64 = 4;
/// Second, larger injected delay: confirms the delay scales with the
/// injected amount rather than being a fixed, coincidental slow path.
const DELAY_2_SECS: u64 = 7;
/// A measured net delay must reach at least this fraction of the injected
/// amount to count as a match.
const DELAY_FRACTION: f64 = 0.6;

/// Build the injected command and its non-executing, length-matched control
/// for one dialect and delay. The control carries the same literal number so
/// a parser that is merely slower on longer input affects both equally.
fn payloads(dialect: &str, original_value: &str, delay_secs: u64) -> (String, String) {
    if dialect == "unix_sleep" {
        (
            format!("{original_value};sleep {delay_secs};"),
            format!("{original_value};echo {delay_secs};"),
        )
    } else {
        // `ping -n` sends one echo immediately then waits ~1s between the
        // rest; `-n (delay+1)` approximates a `delay`-second wait without
        // relying on `timeout`, which refuses to run outside a console.
        let count = delay_secs + 1;
        (
            format!("{original_value}|ping -n {count} 127.0.0.1|"),
            format!("{original_value}|echo {count} 127.0.0.1|"),
        )
    }
}

/// One round at a given delay: both the payload and its control are sent.
/// Returns the net delay and an evidence observation describing both legs,
/// only when both requests succeeded.
async fn measure(
    client: &ProbeClient<'_>,
    original: &str,
    index: usize,
    dialect: &str,
    original_value: &str,
    delay_secs: u64,
    role: &str,
) -> Option<(Duration, ResponseObservation)> {
    let (command, control) = payloads(dialect, original_value, delay_secs);
    let url = mutate_parameter(original, index, &command)?;
    let start = Instant::now();
    let payload_resp = client.get(&url, true, None).await?;
    let payload_elapsed = start.elapsed();
    let control_url = mutate_parameter(original, index, &control)?;
    let start = Instant::now();
    let control_resp = client.get(&control_url, true, None).await?;
    let control_elapsed = start.elapsed();
    if !payload_resp.status.is_success() || !control_resp.status.is_success() {
        return None;
    }
    let net = payload_elapsed.saturating_sub(control_elapsed);
    let excerpt = format!(
        "injected={delay_secs}s payload={:.1}s control={:.1}s net={:.1}s",
        payload_elapsed.as_secs_f64(),
        control_elapsed.as_secs_f64(),
        net.as_secs_f64()
    );
    Some((net, payload_resp.observation(role, &excerpt)))
}

pub(super) async fn check_timing_injection(
    client: &ProbeClient<'_>,
    original: &str,
    params: &[(String, String)],
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(baseline) = client.get(original, true, None).await else {
        return findings;
    };
    if !baseline.status.is_success() {
        client.inconclusive("timing_injection");
        return findings;
    }
    for (index, (parameter, original_value)) in params.iter().enumerate() {
        for dialect in ["unix_sleep", "windows_ping"] {
            if client.stopped() {
                return findings;
            }
            let Some((delta1, observation1)) = measure(
                client,
                original,
                index,
                dialect,
                original_value,
                DELAY_1_SECS,
                "delay_1",
            )
            .await
            else {
                continue;
            };
            #[allow(clippy::cast_precision_loss)] // delay magnitudes are tiny; f64 is exact here
            let delay_1_threshold = DELAY_1_SECS as f64 * DELAY_FRACTION;
            if delta1.as_secs_f64() < delay_1_threshold {
                continue;
            }
            let Some((delta2, observation2)) = measure(
                client,
                original,
                index,
                dialect,
                original_value,
                DELAY_2_SECS,
                "delay_2",
            )
            .await
            else {
                client.inconclusive("timing_injection");
                continue;
            };
            #[allow(clippy::cast_precision_loss)] // delay magnitudes are tiny; f64 is exact here
            let delay_2_threshold = DELAY_2_SECS as f64 * DELAY_FRACTION;
            if delta2.as_secs_f64() < delay_2_threshold || delta2 <= delta1 {
                client.inconclusive("timing_injection");
                continue;
            }
            let point = format!("{parameter} (query position {})", index + 1);
            let (command1, _) = payloads(dialect, original_value, DELAY_1_SECS);
            let Some(url) = mutate_parameter(original, index, &command1) else {
                continue;
            };
            findings.push(attach(
                vuln_finding(
                    session,
                    &url,
                    format!(
                        "command injection timing signal: {dialect} delay scales with injected sleep for {point}"
                    ),
                    Confidence::High,
                ),
                "timing_injection",
                Some(&point),
                EvidenceVerdict::TimingCorrelated,
                vec![baseline.observation("baseline", ""), observation1, observation2],
                "Response delay scales with two distinct injected sleep durations, net of a \
                 length-matched, non-executing control. Timing remains a side channel: network \
                 jitter, slow queries, or rate limiting can produce a similar pattern. OS \
                 command execution is likely, not certain.",
            ));
            break;
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_payload_and_control_share_the_injected_number() {
        let (command, control) = payloads("unix_sleep", "42", 4);
        assert_eq!(command, "42;sleep 4;");
        assert_eq!(control, "42;echo 4;");
    }

    #[test]
    fn windows_payload_and_control_share_the_ping_count() {
        let (command, control) = payloads("windows_ping", "42", 4);
        assert_eq!(command, "42|ping -n 5 127.0.0.1|");
        assert_eq!(control, "42|echo 5 127.0.0.1|");
    }
}
