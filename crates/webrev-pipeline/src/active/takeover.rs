//! Subdomain-takeover fingerprinting (one GET per origin).
//!
//! GETs the origin root and matches the body against the public error pages a
//! few hosting providers serve when a CNAME points at an unclaimed resource.
//! A fingerprint is a lead, not proof: the DNS record must still be checked to
//! confirm it points at a dangling, claimable target.
use super::{client::vuln_finding, evidence::attach, transport::ProbeClient};
use webrev_core::{Confidence, EvidenceVerdict, Finding, SessionId};

/// `(service, lowercase body needle)` for well-known dangling-service pages.
const SIGNATURES: &[(&str, &str)] = &[
    ("GitHub Pages", "there isn't a github pages site here"),
    ("AWS S3", "<code>nosuchbucket</code>"),
    ("AWS S3", "the specified bucket does not exist"),
    ("Heroku", "no such app"),
    ("Fastly", "fastly error: unknown domain"),
    ("Shopify", "sorry, this shop is currently unavailable"),
    ("Surge.sh", "project not found"),
    ("Read the Docs", "unknown to read the docs"),
    ("Netlify", "not found - request id"),
];

pub(super) async fn check_subdomain_takeover(
    client: &ProbeClient<'_>,
    origin: &str,
    session: SessionId,
) -> Option<Finding> {
    let root = format!("{origin}/");
    let response = client.get(&root, true, None).await?;
    let body = response.text().to_ascii_lowercase();
    let (service, needle) = SIGNATURES
        .iter()
        .find(|(_, needle)| body.contains(needle))?;
    Some(attach(
        vuln_finding(
            session,
            &root,
            format!("possible subdomain takeover ({service})"),
            Confidence::Medium,
        ),
        "subdomain_takeover",
        None,
        EvidenceVerdict::Signal,
        vec![response.observation("root", needle)],
        "A dangling-service fingerprint was found in the root response; confirm the DNS record points at an unclaimed resource before reporting.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_matched_case_insensitively() {
        // Mirrors the lowercasing done in `check_subdomain_takeover`.
        let body = "There isn't a GitHub Pages site here.".to_ascii_lowercase();
        let hit = SIGNATURES.iter().find(|(_, n)| body.contains(n));
        assert_eq!(hit.map(|(s, _)| *s), Some("GitHub Pages"));
        let clean = "welcome to our homepage".to_ascii_lowercase();
        assert!(SIGNATURES.iter().all(|(_, n)| !clean.contains(n)));
    }
}
