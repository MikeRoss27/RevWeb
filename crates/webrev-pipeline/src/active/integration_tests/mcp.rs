//! Wire-level fixtures for the MCP tool-exposure check.
use super::*;

fn initialize_reply() -> Reply {
    Reply::json(
        r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","serverInfo":{"name":"fixture","version":"1"}}}"#,
    )
}

#[tokio::test]
async fn anonymous_tool_list_with_privileged_name_is_flagged_high() {
    let fixture = Fixture::new(|request| {
        if request.contains("\"method\":\"initialize\"") {
            initialize_reply()
        } else if request.contains("\"method\":\"tools/list\"") {
            Reply::json(
                r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[
                    {"name":"list_weather_stations"},
                    {"name":"delete_user_account"}
                ]}}"#,
            )
        } else {
            Reply::json(r#"{"error":"unexpected"}"#)
        }
    });
    let findings = scan(&fixture, &["/mcp"], &config()).await;
    let tools = findings
        .iter()
        .find(|f| f.kind == webrev_core::FindingKind::McpTools)
        .expect("mcp tools finding");
    assert!(tools.value.contains("delete_user_account"));
    assert!(tools.value.contains("list_weather_stations"));
    assert_eq!(tools.confidence, webrev_core::Confidence::High);
    assert_eq!(tools.severity(), webrev_core::Severity::High);
    let proof = tools.evidence.as_ref().unwrap();
    assert_eq!(proof.verdict, webrev_core::EvidenceVerdict::Observed);
    assert!(proof.limitation.contains("tools/call"));
    // The MCP Streamable HTTP Accept negotiation actually went out.
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.contains("application/json, text/event-stream")));
}

#[tokio::test]
async fn tool_list_with_no_privileged_names_stays_medium() {
    let fixture = Fixture::new(|request| {
        if request.contains("\"method\":\"initialize\"") {
            initialize_reply()
        } else if request.contains("\"method\":\"tools/list\"") {
            Reply::json(r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_weather"}]}}"#)
        } else {
            Reply::json(r#"{"error":"unexpected"}"#)
        }
    });
    let findings = scan(&fixture, &["/mcp"], &config()).await;
    let tools = findings
        .iter()
        .find(|f| f.kind == webrev_core::FindingKind::McpTools)
        .expect("mcp tools finding");
    assert_eq!(tools.confidence, webrev_core::Confidence::Medium);
    assert_eq!(tools.severity(), webrev_core::Severity::Medium);
    assert!(tools.value.contains("\"privileged_tools\":[]"));
}

#[tokio::test]
async fn a_non_mcp_json_server_produces_no_finding_and_no_tools_list_request() {
    // Doesn't answer like MCP at all: no protocolVersion/serverInfo.
    let fixture = Fixture::new(|_| Reply::json(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#));
    let findings = scan(&fixture, &["/mcp"], &config()).await;
    assert!(!findings
        .iter()
        .any(|f| f.kind == webrev_core::FindingKind::McpTools));
    // tools/list is never sent without a recognisable initialize response.
    assert!(!fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r.contains("\"method\":\"tools/list\"")));
}

#[tokio::test]
async fn an_empty_tool_list_produces_no_finding() {
    let fixture = Fixture::new(|request| {
        if request.contains("\"method\":\"initialize\"") {
            initialize_reply()
        } else {
            Reply::json(r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}"#)
        }
    });
    let findings = scan(&fixture, &["/mcp"], &config()).await;
    assert!(!findings
        .iter()
        .any(|f| f.kind == webrev_core::FindingKind::McpTools));
}

#[tokio::test]
async fn non_mcp_endpoints_are_never_probed() {
    let fixture = Fixture::new(|_| Reply::html("public page"));
    let findings = scan(&fixture, &["/api/users"], &config()).await;
    assert!(!findings
        .iter()
        .any(|f| f.kind == webrev_core::FindingKind::McpTools));
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .all(|r| !r.contains("\"method\":\"initialize\"")));
}
