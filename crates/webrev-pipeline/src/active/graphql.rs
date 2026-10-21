//! GraphQL introspection: GET detection signal, then full schema recovery.
//!
//! For endpoints whose path contains `graphql`, this check does two things:
//!
//! 1. The original, minimal signal: a GET request with a tiny
//!    `{__schema{types{name}}}` query, reported as a `Vulnerability` finding
//!    when the server answers with schema data over GET. Batching and
//!    field-suggestion abuse generally require POST bodies and remain
//!    intentionally out of scope.
//! 2. A full schema recovery: the standard `IntrospectionQuery` document
//!    (GET first; the fixed-literal POST exception documented on
//!    `ProbeClient::post_literal` only if GET does not come back with a
//!    schema) is turned, when it succeeds, into a `FindingKind::GraphQlSchema`
//!    finding naming the discovered query/mutation fields and types — the
//!    actionable deliverable of introspection being enabled, not just the
//!    fact of it.
//!
//! Both steps are read-only: introspection queries schema metadata and
//! cannot mutate application state, regardless of the HTTP verb used to
//! carry the query.
use super::{
    client::vuln_finding,
    evidence::attach,
    transport::{ProbeClient, ProbeResponse},
    urls::{append_query_pair, urlencode},
};
use serde_json::Value;
use webrev_core::{
    Confidence, EvidenceVerdict, Finding, FindingKind, FindingStatus, ProbeEvidence, Provenance,
    SessionId, Source,
};

/// `?query={__schema{types{name}}}`, percent-encoded for the query string.
const INTROSPECTION_SIGNAL_QUERY: &str = "query=%7B__schema%7Btypes%7Bname%7D%7D%7D";

/// The standard GraphQL introspection document (the GraphQL specification's
/// `IntrospectionQuery`), trimmed to the fields this scanner reports
/// (type/field names, not nested argument/interface/directive metadata) to
/// keep the request and the recovered schema bounded.
const FULL_INTROSPECTION_GQL: &str = "query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields(includeDeprecated: true) { name } } } }";

/// The same query, pre-wrapped as the literal JSON POST body. Duplicated
/// rather than built at runtime so `ProbeClient::post_literal`'s `&'static
/// str` body can only ever be this one compile-time constant; the test
/// `post_body_matches_the_get_query` guards the two from drifting apart.
const FULL_INTROSPECTION_POST_BODY: &str = "{\"query\":\"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields(includeDeprecated: true) { name } } } } \"}";

/// Largest number of query/mutation/type names kept per finding. Bounds the
/// finding size against a pathologically large schema without truncating a
/// name mid-string.
const MAX_LISTED: usize = 200;

/// True when the URL path looks like a GraphQL endpoint.
pub(super) fn is_graphql_endpoint(url: &str) -> bool {
    url.split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase()
        .contains("graphql")
}

/// Runs both the legacy GET-only signal and the full schema recovery for one
/// endpoint. Each half is independent: either, both or neither may produce a
/// finding, and a disabled/erroring/out-of-scope target yields none — never a
/// false verdict either way.
pub(super) async fn check_graphql_introspection(
    client: &ProbeClient<'_>,
    url: &str,
    session: SessionId,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(signal) = probe_introspection_signal(client, url, session).await {
        findings.push(signal);
    }
    if let Some(schema) = recover_schema(client, url, session).await {
        findings.push(schema);
    }
    findings
}

async fn probe_introspection_signal(
    client: &ProbeClient<'_>,
    url: &str,
    session: SessionId,
) -> Option<Finding> {
    let probe = append_query_pair(url, INTROSPECTION_SIGNAL_QUERY)?;
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

/// Fetch the full standard introspection document and, if the target returns
/// a parseable schema, name every discovered type/query/mutation field.
/// Tries GET first (cheapest, no verb exception); falls back to the fixed
/// literal POST body (`ProbeClient::post_literal`) only when GET did not
/// yield a schema, since some servers require introspection over POST.
async fn recover_schema(
    client: &ProbeClient<'_>,
    url: &str,
    session: SessionId,
) -> Option<Finding> {
    let get_query = format!("query={}", urlencode(FULL_INTROSPECTION_GQL));
    if let Some(probe) = append_query_pair(url, &get_query) {
        if let Some(response) = client.get(&probe, true, None).await {
            if let Some(finding) = schema_finding(&response, session) {
                return Some(finding);
            }
        }
    }
    let response = client
        .post_literal(url, true, FULL_INTROSPECTION_POST_BODY)
        .await?;
    schema_finding(&response, session)
}

/// Parse a response as a GraphQL introspection result and build the
/// `GraphQlSchema` finding, or `None` when it is not a successful,
/// schema-shaped JSON response (wrong content type, HTTP error, introspection
/// disabled, GraphQL `errors` with no `data`, ...). Never guesses: the
/// absence of a recognisable `__schema` is simply not reported.
fn schema_finding(response: &ProbeResponse, session: SessionId) -> Option<Finding> {
    if !response.status.is_success() {
        return None;
    }
    let content_type = response.content_type();
    if !content_type.contains("json") && !content_type.contains("graphql") {
        return None;
    }
    let body = response.text();
    let doc: Value = serde_json::from_str(&body).ok()?;
    let schema = doc.get("data")?.get("__schema")?;
    let types = schema.get("types")?.as_array()?;

    let named =
        |key: &str| -> Option<String> { schema.get(key)?.get("name")?.as_str().map(str::to_owned) };
    let fields_of = |type_name: &Option<String>| -> Vec<String> {
        let Some(name) = type_name else {
            return Vec::new();
        };
        types
            .iter()
            .find(|t| t.get("name").and_then(Value::as_str) == Some(name.as_str()))
            .and_then(|t| t.get("fields"))
            .and_then(Value::as_array)
            .map(|fields| {
                fields
                    .iter()
                    .filter_map(|f| f.get("name").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    };

    let query_type = named("queryType");
    let mutation_type = named("mutationType");
    let subscription_type = named("subscriptionType");
    let queries = fields_of(&query_type);
    let mutations = fields_of(&mutation_type);
    let type_names: Vec<String> = types
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .filter(|name| !name.starts_with("__"))
        .collect();

    if query_type.is_none() && type_names.is_empty() {
        // Parsed JSON with no recognisable schema shape at all: not a
        // GraphQL introspection response, so nothing is reported.
        return None;
    }

    let summary = serde_json::json!({
        "query_type": query_type,
        "mutation_type": mutation_type,
        "subscription_type": subscription_type,
        "type_count": type_names.len(),
        "query_fields": cap(&queries),
        "mutation_fields": cap(&mutations),
        "types": cap(&type_names),
    });
    let mut finding = Finding::new(
        session,
        FindingKind::GraphQlSchema,
        Some(response.url.clone()),
        summary.to_string(),
        Confidence::High,
        Provenance::new(Source::Active, None),
    );
    finding.status = FindingStatus::Observed;
    finding
        .detectors
        .push("graphql_schema_introspection".into());
    finding.justification = format!(
        "introspection query ({}) returned a parseable __schema: {} types, {} query fields, {} mutation fields",
        response.method,
        type_names.len(),
        queries.len(),
        mutations.len()
    );
    finding.evidence = Some(Box::new(ProbeEvidence {
        check: "graphql_schema_introspection".into(),
        parameter: None,
        verdict: EvidenceVerdict::Observed,
        observations: vec![response.observation("schema probe", &body)],
        limitation: "Only type/field names are recovered (no arguments, interfaces, directives \
            or deprecation reasons); confirm whether introspection is intentionally enabled \
            before reporting."
            .into(),
        diff: Vec::new(),
    }));
    Some(finding)
}

/// Bound a name list to [`MAX_LISTED`] entries without truncating a name.
fn cap(items: &[String]) -> &[String] {
    &items[..items.len().min(MAX_LISTED)]
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

    /// `ProbeClient::post_literal` only accepts a `&'static str`, so the
    /// POST body actually sent can never drift from this module's own GET
    /// query by construction; this test only guards that the duplicated
    /// literal still carries the same query text as a human sanity check.
    #[test]
    fn post_body_matches_the_get_query() {
        assert!(FULL_INTROSPECTION_POST_BODY.contains(FULL_INTROSPECTION_GQL.trim_end()));
    }

    fn response(body: &str) -> ProbeResponse {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        ProbeResponse {
            url: "https://x.test/graphql".into(),
            method: "POST",
            status: reqwest::StatusCode::OK,
            headers,
            bytes: body.as_bytes().to_vec(),
            authenticated: false,
        }
    }

    #[test]
    fn recovers_query_and_mutation_fields_from_a_schema_response() {
        let body = serde_json::json!({
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "subscriptionType": null,
                    "types": [
                        {"kind": "OBJECT", "name": "Query", "fields": [
                            {"name": "user"}, {"name": "users"}
                        ]},
                        {"kind": "OBJECT", "name": "Mutation", "fields": [
                            {"name": "deleteUser"}
                        ]},
                        {"kind": "OBJECT", "name": "User", "fields": [
                            {"name": "id"}, {"name": "email"}
                        ]},
                        {"kind": "SCALAR", "name": "__Type", "fields": null}
                    ]
                }
            }
        })
        .to_string();
        let finding = schema_finding(&response(&body), SessionId::new()).expect("schema");
        assert_eq!(finding.kind, FindingKind::GraphQlSchema);
        assert_eq!(finding.url.as_deref(), Some("https://x.test/graphql"));
        let value: Value = serde_json::from_str(&finding.value).unwrap();
        assert_eq!(value["query_fields"], serde_json::json!(["user", "users"]));
        assert_eq!(value["mutation_fields"], serde_json::json!(["deleteUser"]));
        // __Type (a meta type) is excluded; Query/Mutation/User remain.
        assert_eq!(value["type_count"], 3);
    }

    #[test]
    fn a_non_schema_json_body_yields_no_finding() {
        let body = serde_json::json!({"data": {"hello": "world"}}).to_string();
        assert!(schema_finding(&response(&body), SessionId::new()).is_none());
    }

    #[test]
    fn introspection_disabled_error_yields_no_finding() {
        let body = serde_json::json!({
            "errors": [{"message": "GraphQL introspection is not allowed"}]
        })
        .to_string();
        assert!(schema_finding(&response(&body), SessionId::new()).is_none());
    }

    #[test]
    fn a_non_json_body_yields_no_finding() {
        assert!(schema_finding(&response("<html>not graphql</html>"), SessionId::new()).is_none());
    }

    #[test]
    fn a_failed_status_yields_no_finding() {
        let mut r = response("{}");
        r.status = reqwest::StatusCode::NOT_FOUND;
        assert!(schema_finding(&r, SessionId::new()).is_none());
    }
}
