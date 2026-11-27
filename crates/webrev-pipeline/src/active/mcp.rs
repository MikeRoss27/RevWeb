//! MCP tool-exposure check: an unauthenticated `initialize` + `tools/list`
//! handshake against detected MCP endpoints.
//!
//! Per the Model Context Protocol specification, `initialize` is capability
//! negotiation and `tools/list` is a read-only enumeration of available
//! tools — neither can mutate application state, the same justification
//! `graphql.rs` relies on for its own fixed-literal POST exception. This
//! check goes no further: `tools/call` (actually invoking a tool) is never
//! attempted. Seeing a tool name over an unauthenticated handshake does not
//! establish that invoking it would also succeed unauthenticated, only that
//! its existence and shape are exposed to an anonymous caller — exactly the
//! limitation `docs/active-research.md`'s MCP research note requires this
//! check to carry. Full OAuth authorization-flow testing remains out of
//! scope for a protocol-agnostic active-probe engine.
use super::transport::{ProbeClient, ProbeResponse};
use serde_json::Value;
use webrev_core::{
    Confidence, EvidenceVerdict, Finding, FindingKind, FindingStatus, ProbeEvidence, Provenance,
    SessionId, Source,
};

/// The MCP Streamable HTTP transport requires this exact `Accept` value;
/// many server implementations answer 406 without it.
const MCP_ACCEPT: &str = "application/json, text/event-stream";

/// Fixed-literal JSON-RPC `initialize` request. `protocolVersion` is the
/// latest MCP specification revision at the time this check was written;
/// servers negotiating an older revision still answer with their own
/// `result.protocolVersion`, which this check does not otherwise act on.
const MCP_INITIALIZE_BODY: &str = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\
    \"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\
    \"clientInfo\":{\"name\":\"webrev\",\"version\":\"0.1.0\"}}}";

/// Fixed-literal JSON-RPC `tools/list` request, sent only after a
/// successful `initialize` response.
const MCP_TOOLS_LIST_BODY: &str =
    "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}";

/// Tool-name verbs that suggest a side-effecting or privileged capability
/// (as opposed to a read-only lookup). A name heuristic only: a tool with a
/// harmless-looking name can still mutate state, and this check never calls
/// one to find out.
const PRIVILEGED_VERBS: &[&str] = &[
    "delete", "remove", "drop", "write", "update", "create", "exec", "execute", "run", "shell",
    "eval", "send", "pay", "payment", "transfer", "deploy", "admin", "grant", "revoke", "upload",
    "restart", "shutdown", "migrate",
];

/// Largest number of tool names kept per finding, bounding the finding
/// against a pathologically large tool catalogue without truncating a name.
const MAX_LISTED: usize = 200;

/// True when the URL path looks like an MCP endpoint. A path-substring
/// heuristic, same precision tier as `graphql::is_graphql_endpoint`.
pub(super) fn is_mcp_endpoint(url: &str) -> bool {
    url.split(['?', '#'])
        .next()
        .unwrap_or(url)
        .to_ascii_lowercase()
        .contains("mcp")
}

/// Run the anonymous `initialize` + `tools/list` handshake. Returns `None`
/// whenever the target does not answer like an MCP server, is disabled, or
/// errors — this never guesses from a bare HTTP 200.
pub(super) async fn check_mcp_tool_exposure(
    client: &ProbeClient<'_>,
    url: &str,
    session: SessionId,
) -> Option<Finding> {
    let init = client
        .post_literal_with_accept(url, false, MCP_INITIALIZE_BODY, MCP_ACCEPT)
        .await?;
    if !looks_like_mcp_initialize(&init) {
        return None;
    }
    let list = client
        .post_literal_with_accept(url, false, MCP_TOOLS_LIST_BODY, MCP_ACCEPT)
        .await?;
    tools_finding(&init, &list, session)
}

/// A successful JSON-RPC response carrying `result.protocolVersion` or
/// `result.serverInfo` — the two fields every compliant `initialize`
/// response has, regardless of negotiated capabilities.
fn looks_like_mcp_initialize(response: &ProbeResponse) -> bool {
    if !response.status.is_success() || !response.content_type().contains("json") {
        return false;
    }
    let Ok(doc) = serde_json::from_str::<Value>(&response.text()) else {
        return false;
    };
    let Some(result) = doc.get("result") else {
        return false;
    };
    result.get("protocolVersion").is_some() || result.get("serverInfo").is_some()
}

fn tools_finding(
    init: &ProbeResponse,
    list: &ProbeResponse,
    session: SessionId,
) -> Option<Finding> {
    if !list.status.is_success() || !list.content_type().contains("json") {
        return None;
    }
    let body = list.text();
    let doc: Value = serde_json::from_str(&body).ok()?;
    let tools = doc.get("result")?.get("tools")?.as_array()?;
    if tools.is_empty() {
        return None;
    }
    let names: Vec<String> = tools
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .map(str::to_owned)
        .collect();
    let privileged: Vec<String> = names
        .iter()
        .filter(|name| {
            let lower = name.to_ascii_lowercase();
            PRIVILEGED_VERBS.iter().any(|verb| lower.contains(verb))
        })
        .cloned()
        .collect();
    let summary = serde_json::json!({
        "tool_count": names.len(),
        "tools": cap(&names),
        "privileged_tools": cap(&privileged),
        "anonymous": true,
    });
    let mut finding = Finding::new(
        session,
        FindingKind::McpTools,
        Some(list.url.clone()),
        summary.to_string(),
        if privileged.is_empty() {
            Confidence::Medium
        } else {
            Confidence::High
        },
        Provenance::new(Source::Active, None),
    );
    finding.status = FindingStatus::Observed;
    finding.detectors.push("mcp_tool_exposure".into());
    finding.justification = format!(
        "unauthenticated initialize + tools/list returned {} tool(s), {} privileged-looking",
        names.len(),
        privileged.len()
    );
    finding.evidence = Some(Box::new(ProbeEvidence {
        check: "mcp_tool_exposure".into(),
        parameter: None,
        verdict: EvidenceVerdict::Observed,
        observations: vec![
            init.observation("initialize", ""),
            list.observation("tools_list", &body),
        ],
        limitation: "Listing tools via an unauthenticated initialize + tools/list handshake \
            does not establish that tools/call would also succeed unauthenticated — tools/call \
            was never attempted. Tool listing may be intentionally public. Full OAuth \
            authorization-flow testing is out of scope for this check."
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
    fn mcp_paths_are_recognised() {
        assert!(is_mcp_endpoint("https://ex.com/mcp"));
        assert!(is_mcp_endpoint("https://ex.com/api/MCP/v1"));
        assert!(!is_mcp_endpoint("https://ex.com/api/users"));
    }

    #[test]
    fn privileged_verbs_are_name_substrings_only() {
        assert!(PRIVILEGED_VERBS.iter().any(|v| "delete_user".contains(v)));
        assert!(PRIVILEGED_VERBS.iter().any(|v| "run_shell_cmd".contains(v)));
        assert!(!PRIVILEGED_VERBS
            .iter()
            .any(|v| "list_weather_stations".contains(v)));
    }
}
