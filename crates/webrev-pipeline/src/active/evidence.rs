//! Attach structured proof without deriving exploitability from a keyword.
use webrev_core::{EvidenceVerdict, Finding, ProbeEvidence, ResponseObservation};

pub(super) fn attach(
    mut finding: Finding,
    check: &str,
    parameter: Option<&str>,
    verdict: EvidenceVerdict,
    observations: Vec<ResponseObservation>,
    limitation: &str,
) -> Finding {
    finding.evidence = Some(Box::new(ProbeEvidence {
        check: check.into(),
        parameter: parameter.map(str::to_owned),
        verdict,
        observations,
        limitation: limitation.into(),
    }));
    finding
}
