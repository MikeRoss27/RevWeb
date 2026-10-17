//! Attach structured proof without deriving exploitability from a keyword.
use webrev_core::{EvidenceVerdict, Finding, FindingStatus, ProbeEvidence, ResponseObservation};

pub(super) fn attach(
    mut finding: Finding,
    check: &str,
    parameter: Option<&str>,
    verdict: EvidenceVerdict,
    observations: Vec<ResponseObservation>,
    limitation: &str,
) -> Finding {
    finding.detectors.push(check.into());
    finding.status = match verdict {
        EvidenceVerdict::Observed => FindingStatus::Observed,
        EvidenceVerdict::EvaluationConfirmed
            if check == "template_arithmetic" && observations.len() >= 4 =>
        {
            FindingStatus::Confirmed
        }
        EvidenceVerdict::Signal | EvidenceVerdict::EvaluationConfirmed => FindingStatus::Suspicious,
    };
    finding.justification = limitation.into();
    finding.evidence = Some(Box::new(ProbeEvidence {
        check: check.into(),
        parameter: parameter.map(str::to_owned),
        verdict,
        observations,
        limitation: limitation.into(),
    }));
    finding
}
