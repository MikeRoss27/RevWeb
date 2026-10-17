// crates/webrev-report/src/openapi.rs
//! Reconstruct an `OpenAPI` 3.1 document from a scan session's discovered surface.
//!
//! This "reverses the API from the consumer": instead of describing a service
//! we control, we infer a best-effort specification from the endpoints,
//! parameters and GraphQL operations that static/dynamic/active recon turned
//! up. Everything emitted here is **unverified** — the response shapes were
//! never observed, methods are sometimes guessed, and query parameters cannot
//! be attributed to a specific path. Each object says so in its `description`.
//!
//! ## Determinism
//!
//! Output must be byte-stable across runs so it diffs cleanly and can be
//! checked in. Every collection is a [`BTreeMap`]/[`BTreeSet`], endpoints are
//! sorted before grouping, and `serde_json`'s `Map` is itself `BTreeMap`-backed
//! (no `preserve_order` feature in this workspace), so the serialized key order
//! is stable too.
//!
//! ## Heuristics (documented, deterministic)
//!
//! - **Methods.** Each endpoint's [`Method`](webrev_core::Method) becomes a
//!   path-item operation key. [`Method::Unknown`](webrev_core::Method::Unknown)
//!   endpoints — a bare URL literal with no observed verb — are filed under
//!   `get`, the safest assumption for a consumer-observed resource. When two
//!   endpoints collapse to the same path+method, the first in sorted order wins
//!   (deterministic).
//! - **Path parameters.** `{id}` / `{uuid}` / `{hash}` / `{token}` / any
//!   `{...}` segment produced by [`normalize_url`]
//!   becomes a required `in: path` string parameter at the path-item level
//!   (shared by every method on that path).
//! - **Query parameters.** Discovered [`FindingKind::Parameter`] findings are
//!   request/body/query key *names* with no path attribution in the stored
//!   surface. We therefore (a) register each once under
//!   `components.parameters` as an optional `in: query` string parameter, and
//!   (b) `$ref` the whole set onto every reconstructed operation. This is a
//!   deliberate over-approximation: any discovered parameter *might* apply to
//!   any endpoint, which is exactly the hypothesis a fuzzing consumer wants.
//! - **GraphQL.** We do not reconstruct a GraphQL schema (REST is the focus).
//!   If any [`FindingKind::GraphQl`] findings exist we add a single `/graphql`
//!   path with a `post` operation that lists the observed operation names in
//!   its description, and note the GraphQL surface in `info.description`.

use crate::format::RenderOptions;
use crate::json::SessionReport;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use webrev_core::{normalize_url, FindingKind, Result, WebrevError};

/// The reconstructed `OpenAPI` 3.1 document skeleton. Flexible leaves
/// (parameters, schemas, responses) are [`Value`]s built with `json!`.
#[derive(Serialize)]
struct OpenApiDoc {
    openapi: &'static str,
    info: Info,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    servers: Vec<Server>,
    paths: BTreeMap<String, PathItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    components: Option<Components>,
}

#[derive(Serialize)]
struct Info {
    title: String,
    version: &'static str,
    description: String,
}

#[derive(Serialize)]
struct Server {
    url: String,
}

/// A path-item: shared `parameters` plus one entry per HTTP method. The method
/// map is flattened so its keys (`get`, `post`, …) sit beside `parameters`.
#[derive(Serialize, Default)]
struct PathItem {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    parameters: Vec<Value>,
    #[serde(flatten)]
    operations: BTreeMap<String, Value>,
}

#[derive(Serialize)]
struct Components {
    parameters: BTreeMap<String, Value>,
}

impl SessionReport {
    /// Render the discovered surface as a reconstructed `OpenAPI` 3.1 document.
    ///
    /// Endpoints are scope-filtered like [`render_urls`](Self::render_urls);
    /// `Parameter`/`GraphQl` findings are confidence/severity-filtered like the
    /// other finding-oriented formats via
    /// [`kept_findings`](Self::kept_findings).
    pub(crate) fn render_openapi(&self, opts: RenderOptions) -> Result<String> {
        // Endpoints in scope, sorted for deterministic grouping.
        let mut endpoints: Vec<&webrev_core::Endpoint> = self
            .endpoints
            .iter()
            .filter(|e| opts.scope.matches(e.scope))
            .collect();
        endpoints.sort();

        // Distinct origins -> servers.
        let mut origins: BTreeSet<String> = BTreeSet::new();
        // path -> (method -> source slug); we keep the winning source per op.
        let mut grouped: BTreeMap<String, BTreeMap<String, &'static str>> = BTreeMap::new();

        for ep in &endpoints {
            let normalized = normalize_url(&ep.url);
            let (origin, path) = split_origin_path(&normalized);
            if let Some(origin) = origin {
                origins.insert(origin);
            }
            let method = method_key(ep.method);
            let source = source_slug(ep.source);
            grouped
                .entry(path)
                .or_default()
                .entry(method)
                .or_insert(source); // first (sorted) endpoint wins
        }

        // Query-parameter names discovered across kept findings.
        let query_params: BTreeSet<String> = self
            .kept_findings(opts)
            .filter(|f| f.kind == FindingKind::Parameter)
            .map(|f| f.value.clone())
            .filter(|v| !v.is_empty())
            .collect();

        // components.parameters: one reusable in:query parameter per name.
        // Keyed by a sanitized component name (OpenAPI restricts the key
        // charset); the original name is preserved in the `name` field.
        let mut component_params: BTreeMap<String, Value> = BTreeMap::new();
        for name in &query_params {
            component_params.insert(
                sanitize_component_key(name),
                json!({
                    "name": name,
                    "in": "query",
                    "required": false,
                    "schema": { "type": "string" },
                    "description": "Reconstructed query parameter (discovered name, \
                                    unverified; not attributed to this path).",
                }),
            );
        }

        // $refs to attach the whole query-parameter set onto every operation.
        let query_refs: Vec<Value> = component_params
            .keys()
            .map(|k| json!({ "$ref": format!("#/components/parameters/{k}") }))
            .collect();

        // Build the path items.
        let mut paths: BTreeMap<String, PathItem> = BTreeMap::new();
        for (path, methods) in grouped {
            let path_params = path_parameters(&path);
            let mut item = PathItem {
                parameters: path_params,
                operations: BTreeMap::new(),
            };
            for (method, source) in methods {
                item.operations.insert(
                    method.clone(),
                    operation(&method, &path, source, &query_refs),
                );
            }
            paths.insert(path, item);
        }

        // GraphQL: minimal, single /graphql path if any operations were seen.
        let graphql_ops: BTreeSet<String> = self
            .kept_findings(opts)
            .filter(|f| f.kind == FindingKind::GraphQl)
            .map(|f| f.value.clone())
            .filter(|v| !v.is_empty())
            .collect();
        if !graphql_ops.is_empty() {
            paths.insert("/graphql".to_owned(), graphql_path_item(&graphql_ops));
        }

        let components = if component_params.is_empty() {
            None
        } else {
            Some(Components {
                parameters: component_params,
            })
        };

        let doc = OpenApiDoc {
            openapi: "3.1.0",
            info: Info {
                title: format!("{} (reconstructed API)", self.mission.name),
                version: "reconstructed",
                description: info_description(self, graphql_ops.len()),
            },
            servers: origins.into_iter().map(|url| Server { url }).collect(),
            paths,
            components,
        };

        serde_json::to_string_pretty(&doc)
            .map_err(|e| WebrevError::Config(format!("serializing OpenAPI document: {e}")))
    }
}

/// Human-readable, caveat-first description for the `info` block.
fn info_description(report: &SessionReport, graphql_count: usize) -> String {
    let mut d = String::from(
        "Reconstructed from a webrev recon session by reversing the API from the \
         observed consumer surface. Every path, method and parameter here is \
         UNVERIFIED: response shapes were not observed, some HTTP methods are \
         inferred, and query parameters are not attributed to specific paths.",
    );
    if !report.mission.seeds.is_empty() {
        d.push_str(" Seeds: ");
        d.push_str(&report.mission.seeds.join(", "));
        d.push('.');
    }
    if graphql_count > 0 {
        use std::fmt::Write;
        let _ = write!(
            d,
            " A GraphQL surface was detected ({graphql_count} operation name(s)); \
             its schema is NOT reconstructed — see the /graphql path."
        );
    }
    d
}

/// Split a normalized URL into an optional `scheme://host` origin and a
/// leading-slash path.
fn split_origin_path(url: &str) -> (Option<String>, String) {
    match url.split_once("://") {
        Some((scheme, rest)) => match rest.split_once('/') {
            Some((host, path)) => (Some(format!("{scheme}://{host}")), format!("/{path}")),
            None => (Some(format!("{scheme}://{rest}")), "/".to_owned()),
        },
        None if url.starts_with('/') => (None, url.to_owned()),
        None => (None, format!("/{url}")),
    }
}

/// Lower-case `OpenAPI` path-item key for a method; `Unknown` -> `get`.
fn method_key(method: webrev_core::Method) -> String {
    use webrev_core::Method;
    match method {
        Method::Get | Method::Unknown => "get",
        Method::Post => "post",
        Method::Put => "put",
        Method::Delete => "delete",
        Method::Patch => "patch",
        Method::Head => "head",
        Method::Options => "options",
    }
    .to_owned()
}

fn source_slug(source: webrev_core::Source) -> &'static str {
    use webrev_core::Source;
    match source {
        Source::Browser => "browser",
        Source::JsAst => "js-ast",
        Source::JsRegex => "js-regex",
        Source::Html => "html",
        Source::SourceMap => "sourcemap",
        Source::Manifest => "manifest",
        Source::Active => "active",
    }
}

/// Path-level parameters derived from `{...}` placeholder segments.
fn path_parameters(path: &str) -> Vec<Value> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut out = Vec::new();
    for segment in path.split('/') {
        if let Some(name) = segment
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .filter(|s| !s.is_empty())
        {
            if seen.insert(name) {
                out.push(json!({
                    "name": name,
                    "in": "path",
                    "required": true,
                    "schema": { "type": "string" },
                    "description": "Reconstructed from a normalized volatile path \
                                    segment; unverified.",
                }));
            }
        }
    }
    out
}

/// Build one operation object, tagged by provenance source, with the shared
/// query-parameter `$ref`s attached.
fn operation(method: &str, path: &str, source: &str, query_refs: &[Value]) -> Value {
    json!({
        "summary": format!("{} {path} (reconstructed)", method.to_ascii_uppercase()),
        "description": format!(
            "Reconstructed from the observed consumer surface (source: {source}); \
             UNVERIFIED. Response shape was not observed."
        ),
        "tags": [source],
        "parameters": query_refs,
        "responses": {
            "default": {
                "description": "Unobserved — response shape was not captured during recon.",
            }
        },
    })
}

/// The single `/graphql` path item listing the observed operation names.
fn graphql_path_item(ops: &BTreeSet<String>) -> PathItem {
    let names: Vec<&str> = ops.iter().map(String::as_str).collect();
    let op = json!({
        "summary": "GraphQL endpoint (reconstructed)",
        "description": format!(
            "A GraphQL surface was detected during recon. The schema is NOT \
             reconstructed; only these observed operation names are reported: {}. \
             UNVERIFIED.",
            names.join(", ")
        ),
        "tags": ["graphql"],
        "responses": {
            "default": { "description": "Unobserved GraphQL response." }
        },
    });
    let mut operations = BTreeMap::new();
    operations.insert("post".to_owned(), op);
    PathItem {
        parameters: Vec::new(),
        operations,
    }
}

/// Sanitize a parameter name into a valid `components.parameters` key.
/// `OpenAPI` restricts component keys to `[a-zA-Z0-9._-]`; anything else becomes
/// `_`. Empty results fall back to `param`.
fn sanitize_component_key(name: &str) -> String {
    let key: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if key.is_empty() {
        "param".to_owned()
    } else {
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{RenderOptions, ScopeFilter};
    use webrev_core::{
        Confidence, Endpoint, EndpointScope, Finding, FindingKind, Method, Mission, Provenance,
        Scope, Severity, Source,
    };

    fn report() -> SessionReport {
        let mission = Mission::new(
            "acme",
            Scope::new(vec!["x.test".into()], vec![]),
            vec!["https://x.test/".into()],
        );
        let sid = mission.id;
        let findings = vec![
            Finding::new(
                sid,
                FindingKind::Parameter,
                None,
                "search",
                Confidence::High,
                Provenance::new(Source::JsAst, None),
            ),
            Finding::new(
                sid,
                FindingKind::GraphQl,
                None,
                "query GetUser",
                Confidence::High,
                Provenance::new(Source::JsAst, None),
            ),
        ];
        let endpoints = vec![
            Endpoint::new("https://x.test/api/users/{id}", Method::Get, Source::JsAst),
            Endpoint::new("https://x.test/api/users", Method::Post, Source::Browser),
            Endpoint::new("https://cdn.other/lib.js", Method::Unknown, Source::JsRegex)
                .with_scope(EndpointScope::External),
        ];
        SessionReport::build(mission, findings, endpoints)
    }

    fn opts(scope: ScopeFilter) -> RenderOptions {
        RenderOptions {
            format: crate::ReportFormat::OpenApi,
            scope,
            min_confidence: Confidence::Low,
            min_severity: Severity::Info,
        }
    }

    fn doc(scope: ScopeFilter) -> Value {
        let s = report().render_openapi(opts(scope)).unwrap();
        serde_json::from_str(&s).expect("valid JSON")
    }

    #[test]
    fn parses_as_json_and_declares_openapi_31() {
        let v = doc(ScopeFilter::All);
        assert_eq!(v["openapi"], "3.1.0");
        assert_eq!(v["info"]["version"], "reconstructed");
        assert!(v["info"]["title"].as_str().unwrap().contains("acme"));
    }

    #[test]
    fn paths_present_for_sample_endpoints() {
        let v = doc(ScopeFilter::All);
        let paths = v["paths"].as_object().unwrap();
        assert!(paths.contains_key("/api/users"));
        assert!(paths.contains_key("/api/users/{id}"));
        // POST endpoint keeps its verb; the GET path has a get operation.
        assert!(v["paths"]["/api/users"]["post"].is_object());
        assert!(v["paths"]["/api/users/{id}"]["get"].is_object());
    }

    #[test]
    fn id_segment_becomes_in_path_parameter() {
        let v = doc(ScopeFilter::All);
        let params = v["paths"]["/api/users/{id}"]["parameters"]
            .as_array()
            .unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0]["name"], "id");
        assert_eq!(params[0]["in"], "path");
        assert_eq!(params[0]["required"], true);
        assert_eq!(params[0]["schema"]["type"], "string");
    }

    #[test]
    fn servers_list_in_scope_origin_only() {
        let v = doc(ScopeFilter::All);
        let servers = v["servers"].as_array().unwrap();
        // External cdn.other endpoint is still in-scope-filtered out only when
        // scope=Internal; with All both origins appear.
        let urls: Vec<&str> = servers.iter().map(|s| s["url"].as_str().unwrap()).collect();
        assert!(urls.contains(&"https://x.test"));
        assert!(urls.contains(&"https://cdn.other"));

        let internal = doc(ScopeFilter::Internal);
        let urls: Vec<&str> = internal["servers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["url"].as_str().unwrap())
            .collect();
        assert_eq!(urls, vec!["https://x.test"]);
    }

    #[test]
    fn query_params_registered_and_referenced() {
        let v = doc(ScopeFilter::All);
        // Registered as a reusable component.
        assert_eq!(v["components"]["parameters"]["search"]["in"], "query");
        // Referenced from an operation.
        let op_params = v["paths"]["/api/users"]["post"]["parameters"]
            .as_array()
            .unwrap();
        assert!(op_params
            .iter()
            .any(|p| p["$ref"] == "#/components/parameters/search"));
    }

    #[test]
    fn graphql_surface_gets_a_path_and_info_note() {
        let v = doc(ScopeFilter::All);
        assert!(v["paths"]["/graphql"]["post"].is_object());
        assert!(v["info"]["description"]
            .as_str()
            .unwrap()
            .contains("GraphQL"));
    }

    #[test]
    fn output_is_deterministic() {
        let a = report().render_openapi(opts(ScopeFilter::All)).unwrap();
        let b = report().render_openapi(opts(ScopeFilter::All)).unwrap();
        assert_eq!(a, b);
    }
}
