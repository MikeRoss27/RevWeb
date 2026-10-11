//! Bounded arithmetic-only template probes with two independent results.
use super::{
    client::vuln_finding, evidence::attach, transport::ProbeClient, urls::mutate_parameter,
};
use webrev_core::{Confidence, EvidenceVerdict, Finding, SessionId};

/// A calculated expression is evidence of evaluation, never a claim that OS
/// commands executed. No shell, filesystem writes, timing sleeps or callbacks.
pub(super) async fn check_expressions(
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
        client.inconclusive("template_arithmetic");
        return findings;
    }
    for (index, (parameter, original_value)) in params.iter().enumerate() {
        for dialect in ["braces", "dollar"] {
            if client.stopped() {
                return findings;
            }
            let nonce = rand::random::<u64>();
            let prefix = format!("wrvEval{nonce:016x}L");
            let suffix = "Rend";
            let a = 101 + nonce % 797;
            let b = 103 + (nonce >> 16) % 787;
            let expression = |left, right| match dialect {
                "braces" => format!("{{{{{left}*{right}}}}}"),
                _ => format!("${{{left}*{right}}}"),
            };
            let expected = format!("{prefix}{}{suffix}", a * b);
            let payload = format!("{prefix}{}{suffix}", expression(a, b));
            let Some(url) = mutate_parameter(original, index, &payload) else {
                continue;
            };
            let Some(first) = client.get(&url, true, None).await else {
                continue;
            };
            if !first.status.is_success()
                || !first.text().contains(&expected)
                || baseline.text().contains(&expected)
            {
                continue;
            }
            let second_expected = format!("{prefix}{}{suffix}", (a + 7) * (b + 11));
            let second_payload = format!("{prefix}{}{suffix}", expression(a + 7, b + 11));
            let Some(second_url) = mutate_parameter(original, index, &second_payload) else {
                continue;
            };
            let Some(second) = client.get(&second_url, true, None).await else {
                continue;
            };
            if !second.status.is_success()
                || !second.text().contains(&second_expected)
                || second.text().contains(&expected)
            {
                client.inconclusive("template_arithmetic");
                continue;
            }
            // Same nonce, no expression: catches caches and control contamination.
            let Some(control_url) = mutate_parameter(
                original,
                index,
                &format!("{prefix}{original_value}{suffix}"),
            ) else {
                continue;
            };
            let Some(control) = client.get(&control_url, true, None).await else {
                continue;
            };
            if !control.status.is_success()
                || control.text().contains(&expected)
                || control.text().contains(&second_expected)
            {
                client.inconclusive("template_arithmetic");
                continue;
            }
            let point = format!("{parameter} (query position {})", index + 1);
            findings.push(attach(
                vuln_finding(session, &url, format!("template expression evaluation: {dialect} arithmetic computed twice for {point}"), Confidence::High),
                "template_arithmetic", Some(&point), EvidenceVerdict::EvaluationConfirmed,
                vec![baseline.observation("baseline", ""), first.observation("arithmetic_1", &expected),
                    second.observation("arithmetic_2", &second_expected), control.observation("payload_free_control", "")],
                "Confirms arithmetic expression evaluation. Engine identity, unintended access and OS command execution remain unproven.",
            ));
            break;
        }
    }
    findings
}
