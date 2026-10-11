//! GraphQL introspection detection over GET.
//!
//! For endpoints whose path contains `graphql`, attempt a minimal
//! introspection query over GET and look for `__schema` / `queryType` in a
//! JSON response. Batching and field-suggestion abuse generally require POST
//! bodies and are intentionally out of scope for this GET-only scanner.
use super::{
    client::vuln_finding, evidence::attach, transport::ProbeClient, urls::append_query_pair,
};
use webrev_core::{Confidence, EvidenceVerdict, Finding, SessionId};

/// `?query={__schema{types{name}}}`, percent-encoded for the query string.
const INTROSPECTION_QUERY: &str = "query=%7B__schema%7Btypes%7Bname%7D%7D%7D";

/// True when the URL path looks like a GraphQL endpoint.
pub(super) fn is_graphql_endpoint(url: &str) -> bool {
    url.split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase()
        .contains("graphql")
}

pub(super) async fn check_graphql_introspection(
    client: &ProbeClient<'_>,
    url: &str,
    session: SessionId,
) -> Option<Finding> {
    let probe = append_query_pair(url, INTROSPECTION_QUERY)?;
    let response = client.get(&probe, true, None).await?;
    if !response.status.is_success() {
        return None;
    }
    let content_type = response.content_type();
    if !content_type.contains("json") && !content_type.contains("graphql") {
        return None;
    }
    let body = response.text();
    if !body.contains("__schema") && !body.contains("queryType") {
        return None;
    }
    Some(attach(
        vuln_finding(
            session,
            &probe,
            "graphql introspection enabled: __schema returned over GET",
            Confidence::Medium,
        ),
        "graphql_introspection",
        None,
        EvidenceVerdict::Observed,
        vec![response.observation("probe", "__schema")],
        "Introspection is often intentionally enabled outside production; confirm the environment before reporting. POST-only batching/field-suggestion abuse was not attempted.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphql_paths_are_recognised() {
        assert!(is_graphql_endpoint("https://ex.com/graphql"));
        assert!(is_graphql_endpoint("https://ex.com/api/GraphQL?x=1"));
        assert!(!is_graphql_endpoint("https://ex.com/api/users"));
    }
}
