//! Evidence-backed relationships between endpoints, source components, and parameters.
//!
//! A parameter found in a script is linked to that script. It is linked to an
//! endpoint only when the parameter finding names the endpoint URL, a probe
//! names both, or the parameter occurs in the endpoint's own query string.
//! Sharing a script alone does not prove that every endpoint uses every key.

use crate::{format::RenderOptions, json::SessionReport};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use webrev_core::{normalize_url, Endpoint, Finding, FindingKind, Method, Source};

#[derive(Clone)]
struct Node {
    kind: &'static str,
    label: String,
    scope: Option<String>,
    confidence: Option<u8>,
}

/// Hard bound on the exported relation graph: a session with a very large
/// number of findings must make the graph incomplete rather than unbounded.
/// This is a presentation-layer bound on top of the crawl's own budgets
/// (`max_pages` etc.), not a replacement for them.
const MAX_GRAPH_NODES: usize = 5_000;
const MAX_GRAPH_EDGES: usize = 20_000;

#[derive(Default)]
struct RelationGraph {
    nodes: BTreeMap<String, Node>,
    edges: BTreeSet<(String, String, &'static str)>,
    /// Set once a node or edge was dropped for being over a bound above,
    /// rather than for lacking evidence. Rendered as an explicit marker so a
    /// truncated graph is never mistaken for a complete one.
    truncated: bool,
}

impl RelationGraph {
    fn node(
        &mut self,
        key: String,
        kind: &'static str,
        label: String,
        scope: Option<String>,
        confidence: Option<u8>,
    ) {
        if self.nodes.contains_key(&key) {
            return;
        }
        if self.nodes.len() >= MAX_GRAPH_NODES {
            self.truncated = true;
            return;
        }
        self.nodes.insert(
            key,
            Node {
                kind,
                label,
                scope,
                confidence,
            },
        );
    }

    /// No-ops (rather than panicking at render time) when either endpoint
    /// was dropped by the node cap above, so a capped graph still renders.
    fn edge(&mut self, from: String, to: String, relation: &'static str) {
        if !self.nodes.contains_key(&from) || !self.nodes.contains_key(&to) {
            return;
        }
        if self.edges.len() >= MAX_GRAPH_EDGES {
            self.truncated = true;
            return;
        }
        self.edges.insert((from, to, relation));
    }
}

fn endpoint_key(endpoint: &Endpoint) -> String {
    format!("endpoint:{} {}", endpoint.method, endpoint.url)
}

fn component_key(location: &str) -> String {
    format!("component:{location}")
}

/// A `component` node is a location findings carry provenance to, covering
/// both pages and script/stylesheet sources. Classifying it by file
/// extension is a strictly cosmetic refinement of the existing "component"
/// key namespace (so every prior edge/key stays byte-identical) — it does
/// not add or remove any relation.
fn component_kind(location: &str) -> &'static str {
    let path = location.split(['?', '#']).next().unwrap_or(location);
    let ext = path
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "js" | "mjs" | "cjs" => "script",
        "css" => "stylesheet",
        "map" => "sourcemap",
        _ => "document",
    }
}

fn parameter_key(name: &str) -> String {
    format!("parameter:{name}")
}

fn resource_key(target: &str) -> String {
    format!("resource:{target}")
}

fn framework_key(name: &str) -> String {
    format!("framework:{name}")
}

/// A `Script`/`Link`/`SourceMap` finding's reference target, kept only when
/// it is absolute or root-relative. A bare relative reference (`app.js`)
/// would need resolving against the page's base URL to name a real
/// resource, and this report layer never re-resolves URLs the crawler
/// already resolved and then discarded — so it is skipped rather than
/// guessed at, the same honesty tradeoff `source_locations` already makes.
fn target_ref(finding: &Finding) -> Option<&str> {
    let url = finding.url.as_deref()?;
    (url.starts_with("http://") || url.starts_with("https://") || url.starts_with('/'))
        .then_some(url)
}

fn query_names(url: &str) -> impl Iterator<Item = &str> {
    url.split_once('?')
        .map(|(_, query)| query.split('#').next().unwrap_or_default())
        .unwrap_or_default()
        .split('&')
        .filter_map(|part| {
            part.split_once('=')
                .map_or(Some(part), |(name, _)| Some(name))
        })
        .filter(|name| !name.is_empty())
}

fn source_locations(finding: &Finding) -> BTreeSet<&str> {
    finding
        .provenances
        .iter()
        .chain(std::iter::once(&finding.provenance))
        .filter(|p| p.source != Source::Active)
        .filter_map(|p| p.location.as_deref())
        .filter(|location| {
            location.starts_with("http://")
                || location.starts_with("https://")
                || location.starts_with('/')
        })
        .collect()
}

fn url_path(url: &str) -> &str {
    let path = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split_once('/').map(|(_, path)| path))
        .unwrap_or(url);
    path.trim_start_matches('/')
}

/// Match an endpoint finding to one stored endpoint. A relative finding URL
/// can match an absolute stored URL only if that path is unique in the report.
fn matching_endpoint<'a>(finding: &Finding, endpoints: &'a [&Endpoint]) -> Option<&'a Endpoint> {
    let url = finding.url.as_deref()?;
    let method = finding
        .value
        .split_whitespace()
        .next()
        .map_or(Method::Unknown, Method::parse);
    let normalized = normalize_url(url);
    let candidates: Vec<_> = endpoints
        .iter()
        .copied()
        .filter(|e| method == Method::Unknown || e.method == method)
        .filter(|e| {
            e.url == normalized
                || (!url.contains("://") && url_path(&e.url) == url_path(&normalized))
        })
        .collect();
    (candidates.len() == 1).then(|| candidates[0])
}

/// Record `relation` from every location a `Script`/`Link`/`SourceMap`
/// finding was found in to its reference target, when that target is a
/// trustworthy node key (see `target_ref`).
fn add_resource_edge(graph: &mut RelationGraph, finding: &Finding, relation: &'static str) {
    let Some(target) = target_ref(finding) else {
        return;
    };
    let resource = resource_key(target);
    graph.node(resource.clone(), "resource", target.to_owned(), None, None);
    link_component(graph, finding, &resource, relation);
}

/// Record `relation` from every location `finding` carries provenance to,
/// toward an already-keyed node (`to`). Shared by every finding kind whose
/// edge is "this was found at this component", so the component node
/// itself (keying, classification) is created in exactly one place.
fn link_component(graph: &mut RelationGraph, finding: &Finding, to: &str, relation: &'static str) {
    for location in source_locations(finding) {
        let component = component_key(location);
        graph.node(
            component.clone(),
            component_kind(location),
            location.to_owned(),
            None,
            None,
        );
        graph.edge(component, to.to_owned(), relation);
    }
}

impl SessionReport {
    fn relation_graph(&self, opts: RenderOptions) -> RelationGraph {
        let endpoints: Vec<_> = self
            .endpoints
            .iter()
            .filter(|e| opts.scope.matches(e.scope))
            .collect();
        let mut graph = RelationGraph::default();
        for endpoint in &endpoints {
            let key = endpoint_key(endpoint);
            graph.node(
                key.clone(),
                "endpoint",
                format!("{} {}", endpoint.method, endpoint.url),
                Some(endpoint.scope.slug().to_owned()),
                Some(endpoint.confidence.score()),
            );
            for name in query_names(&endpoint.url) {
                let parameter = parameter_key(name);
                graph.node(parameter.clone(), "parameter", name.to_owned(), None, None);
                graph.edge(key.clone(), parameter, "has_parameter");
            }
        }

        for finding in self.kept_findings(opts) {
            match finding.kind {
                FindingKind::Endpoint => {
                    if let Some(endpoint) = matching_endpoint(finding, &endpoints) {
                        let ep_key = endpoint_key(endpoint);
                        if let Some(url) = finding.url.as_deref() {
                            for name in query_names(url) {
                                let parameter = parameter_key(name);
                                graph.node(
                                    parameter.clone(),
                                    "parameter",
                                    name.to_owned(),
                                    None,
                                    None,
                                );
                                graph.edge(ep_key.clone(), parameter, "has_parameter");
                            }
                        }
                        link_component(&mut graph, finding, &ep_key, "reveals");
                    }
                }
                FindingKind::Parameter => {
                    let name = finding.value.trim();
                    if name.is_empty() {
                        continue;
                    }
                    let parameter = parameter_key(name);
                    graph.node(parameter.clone(), "parameter", name.to_owned(), None, None);
                    link_component(&mut graph, finding, &parameter, "mentions_parameter");
                    if let Some(endpoint) = matching_endpoint(finding, &endpoints) {
                        graph.edge(endpoint_key(endpoint), parameter, "has_parameter");
                    }
                }
                // Direct fact only: a technology detected at a location is
                // linked to that location, never chained onward to an
                // endpoint the same location happens to also reveal — that
                // transitivity was deliberately rejected already (see
                // `docs/roadmap.md`, §4, "Non fait").
                FindingKind::Technology => {
                    let name = finding.value.trim();
                    if name.is_empty() {
                        continue;
                    }
                    let framework = framework_key(name);
                    graph.node(framework.clone(), "framework", name.to_owned(), None, None);
                    link_component(&mut graph, finding, &framework, "detected_on");
                }
                // Structural crawl relations: a page already known to load a
                // script, link to another page, or a script already known
                // to map to a source map. This is a direct reading of
                // provenance webrev already records (`html.rs`/
                // `sourcemaps.rs` extractors), not a second discovery pass —
                // see `docs/asgc-plan.md` ("pas un second système
                // parallèle").
                FindingKind::Script => add_resource_edge(&mut graph, finding, "loads"),
                FindingKind::Link => add_resource_edge(&mut graph, finding, "links_to"),
                FindingKind::SourceMap => add_resource_edge(&mut graph, finding, "maps_to"),
                FindingKind::Vulnerability | FindingKind::Idor => {
                    if let Some(evidence) = &finding.evidence {
                        if let Some(name) = evidence.parameter.as_deref().filter(|s| !s.is_empty())
                        {
                            let parameter = parameter_key(name);
                            graph.node(parameter.clone(), "parameter", name.to_owned(), None, None);
                            if let Some(endpoint) = matching_endpoint(finding, &endpoints) {
                                graph.edge(endpoint_key(endpoint), parameter, "probed_parameter");
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        graph
    }

    /// Render a Graphviz DOT document. Node IDs are generated from sorted keys.
    #[must_use]
    pub fn render_dot(&self, opts: RenderOptions) -> String {
        let graph = self.relation_graph(opts);
        let ids: BTreeMap<_, _> = graph
            .nodes
            .keys()
            .enumerate()
            .map(|(i, key)| (key.as_str(), format!("n{i}")))
            .collect();
        let mut out = String::from("digraph webrev {\n");
        if graph.truncated {
            out.push_str("  // truncated: true (graph exceeded its node/edge bound)\n");
        }
        for (key, node) in &graph.nodes {
            let _ = write!(
                out,
                "  {} [label=\"{}\", kind=\"{}\"",
                ids[key.as_str()],
                dot_escape(&node.label),
                node.kind
            );
            if let Some(scope) = &node.scope {
                let _ = write!(out, ", scope=\"{scope}\"");
            }
            if let Some(confidence) = node.confidence {
                let _ = write!(out, ", confidence={confidence}");
            }
            out.push_str("];\n");
        }
        for (from, to, relation) in &graph.edges {
            let _ = writeln!(
                out,
                "  {} -> {} [label=\"{relation}\"];",
                ids[from.as_str()],
                ids[to.as_str()]
            );
        }
        out.push_str("}\n");
        out
    }

    /// Render `GraphML` with typed node and edge attributes.
    #[must_use]
    pub fn render_graphml(&self, opts: RenderOptions) -> String {
        let graph = self.relation_graph(opts);
        let ids: BTreeMap<_, _> = graph
            .nodes
            .keys()
            .enumerate()
            .map(|(i, key)| (key.as_str(), format!("n{i}")))
            .collect();
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n  <key id=\"kind\" for=\"node\" attr.name=\"kind\" attr.type=\"string\"/>\n  <key id=\"label\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n  <key id=\"scope\" for=\"node\" attr.name=\"scope\" attr.type=\"string\"/>\n  <key id=\"confidence\" for=\"node\" attr.name=\"confidence\" attr.type=\"int\"/>\n  <key id=\"relation\" for=\"edge\" attr.name=\"relation\" attr.type=\"string\"/>\n  <key id=\"truncated\" for=\"graph\" attr.name=\"truncated\" attr.type=\"boolean\"/>\n  <graph id=\"webrev\" edgedefault=\"directed\">\n");
        if graph.truncated {
            out.push_str("    <data key=\"truncated\">true</data>\n");
        }
        for (key, node) in &graph.nodes {
            let _ = write!(
                out,
                "    <node id=\"{}\"><data key=\"kind\">{}</data><data key=\"label\">{}</data>",
                ids[key.as_str()],
                node.kind,
                xml_escape(&node.label)
            );
            if let Some(scope) = &node.scope {
                let _ = write!(out, "<data key=\"scope\">{scope}</data>");
            }
            if let Some(confidence) = node.confidence {
                let _ = write!(out, "<data key=\"confidence\">{confidence}</data>");
            }
            out.push_str("</node>\n");
        }
        for (i, (from, to, relation)) in graph.edges.iter().enumerate() {
            let _ = writeln!(out,
                "    <edge id=\"e{i}\" source=\"{}\" target=\"{}\"><data key=\"relation\">{relation}</data></edge>",
                ids[from.as_str()], ids[to.as_str()]
            );
        }
        out.push_str("  </graph>\n</graphml>\n");
        out
    }
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReportFormat, ScopeFilter};
    use webrev_core::{Confidence, EndpointScope, Mission, Provenance, Scope, Severity};

    fn opts(format: ReportFormat) -> RenderOptions {
        RenderOptions {
            format,
            scope: ScopeFilter::Internal,
            min_confidence: Confidence::Low,
            min_severity: Severity::Info,
            redact: false,
        }
    }

    fn sample() -> SessionReport {
        let mission = Mission::new("graph", Scope::new(vec!["x.test".into()], vec![]), vec![]);
        let sid = mission.id;
        let script = "https://x.test/app.js";
        let endpoint = Finding::new(
            sid,
            FindingKind::Endpoint,
            Some("/api/search?q=1".into()),
            "GET /api/search?q=1",
            Confidence::High,
            Provenance::new(Source::JsAst, Some(script.into())),
        );
        let parameter = Finding::new(
            sid,
            FindingKind::Parameter,
            None,
            "bodyKey",
            Confidence::Low,
            Provenance::new(Source::JsRegex, Some(script.into())),
        );
        let external = Endpoint::new("https://other.test/api", Method::Get, Source::Html)
            .with_scope(EndpointScope::External);
        SessionReport::build(
            mission,
            vec![endpoint, parameter],
            vec![
                Endpoint::new("https://x.test/api/search", Method::Get, Source::JsAst),
                external,
            ],
        )
    }

    #[test]
    fn only_observed_relations_are_exported() {
        let graph = sample().relation_graph(opts(ReportFormat::Dot));
        let ep = "endpoint:GET https://x.test/api/search".to_owned();
        let component = "component:https://x.test/app.js".to_owned();
        let query = "parameter:q".to_owned();
        let body = "parameter:bodyKey".to_owned();
        assert!(graph
            .edges
            .contains(&(component.clone(), ep.clone(), "reveals")));
        assert!(graph.edges.contains(&(ep.clone(), query, "has_parameter")));
        assert!(graph
            .edges
            .contains(&(component, body.clone(), "mentions_parameter")));
        assert!(!graph
            .edges
            .iter()
            .any(|(from, to, _)| from == &ep && to == &body));
        assert!(!graph
            .nodes
            .contains_key("endpoint:GET https://other.test/api"));
    }

    #[test]
    fn exports_escape_labels_and_are_deterministic() {
        let mut report = sample();
        report.findings.push(Finding::new(
            report.mission.id,
            FindingKind::Parameter,
            None,
            "x<&\"",
            Confidence::Low,
            Provenance::new(Source::JsRegex, Some("https://x.test/app.js".into())),
        ));
        let dot = report.render(opts(ReportFormat::Dot)).unwrap();
        assert!(dot.contains("x<&\\\""));
        assert_eq!(dot, report.render(opts(ReportFormat::Dot)).unwrap());
        let graphml = report.render(opts(ReportFormat::GraphMl)).unwrap();
        assert!(graphml.contains("x&lt;&amp;&quot;"));
        assert!(graphml.contains("edgedefault=\"directed\""));
        assert_eq!(graphml, report.render(opts(ReportFormat::GraphMl)).unwrap());
    }

    #[test]
    fn structural_crawl_relations_are_exported() {
        let mission = Mission::new("graph", Scope::new(vec!["x.test".into()], vec![]), vec![]);
        let sid = mission.id;
        let page = "https://x.test/";
        let script = Finding::new(
            sid,
            FindingKind::Script,
            Some("/app.js".into()),
            "/app.js",
            Confidence::High,
            Provenance::new(Source::Html, Some(page.into())),
        );
        let link = Finding::new(
            sid,
            FindingKind::Link,
            Some("/about".into()),
            "/about",
            Confidence::Low,
            Provenance::new(Source::Html, Some(page.into())),
        );
        let bare_relative_link = Finding::new(
            sid,
            FindingKind::Link,
            Some("contact".into()),
            "contact",
            Confidence::Low,
            Provenance::new(Source::Html, Some(page.into())),
        );
        let map = Finding::new(
            sid,
            FindingKind::SourceMap,
            Some("/app.js.map".into()),
            "/app.js.map",
            Confidence::High,
            Provenance::new(Source::SourceMap, Some("https://x.test/app.js".into())),
        );
        let report =
            SessionReport::build(mission, vec![script, link, bare_relative_link, map], vec![]);
        let graph = report.relation_graph(opts(ReportFormat::Dot));

        let doc = component_key(page);
        let app_js = resource_key("/app.js");
        let about = resource_key("/about");
        let app_js_map = resource_key("/app.js.map");
        let script_as_doc = component_key("https://x.test/app.js");

        assert!(graph
            .edges
            .contains(&(doc.clone(), app_js.clone(), "loads")));
        assert!(graph.edges.contains(&(doc, about, "links_to")));
        assert!(graph
            .edges
            .contains(&(script_as_doc, app_js_map, "maps_to")));
        // A bare relative href ("contact") is never guessed at: no edge, no
        // fabricated resource node, since this layer does not re-resolve
        // URLs the crawler already resolved and discarded.
        assert!(!graph.nodes.contains_key(&resource_key("contact")));
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|(_, _, rel)| *rel == "links_to")
                .count(),
            1
        );
    }

    #[test]
    fn relation_graph_truncates_rather_than_growing_unbounded() {
        let mission = Mission::new("graph", Scope::new(vec!["x.test".into()], vec![]), vec![]);
        let sid = mission.id;
        let findings: Vec<Finding> = (0..MAX_GRAPH_NODES + 10)
            .map(|i| {
                Finding::new(
                    sid,
                    FindingKind::Parameter,
                    None,
                    format!("param{i}"),
                    Confidence::Low,
                    Provenance::new(Source::JsRegex, Some("https://x.test/app.js".into())),
                )
            })
            .collect();
        let report = SessionReport::build(mission, findings, vec![]);
        let graph = report.relation_graph(opts(ReportFormat::Dot));
        assert!(graph.truncated);
        assert!(graph.nodes.len() <= MAX_GRAPH_NODES);

        let dot = report.render(opts(ReportFormat::Dot)).unwrap();
        assert!(dot.contains("truncated: true"));
        let graphml = report.render(opts(ReportFormat::GraphMl)).unwrap();
        assert!(graphml.contains("<data key=\"truncated\">true</data>"));
    }

    #[test]
    fn component_kind_is_classified_by_extension() {
        assert_eq!(component_kind("https://x.test/app.js"), "script");
        assert_eq!(component_kind("https://x.test/app.mjs?v=2"), "script");
        assert_eq!(component_kind("https://x.test/style.css"), "stylesheet");
        assert_eq!(component_kind("https://x.test/app.js.map"), "sourcemap");
        assert_eq!(component_kind("https://x.test/"), "document");
        assert_eq!(component_kind("https://x.test/about"), "document");
    }

    #[test]
    fn technology_links_directly_to_its_location_only() {
        let mission = Mission::new("graph", Scope::new(vec!["x.test".into()], vec![]), vec![]);
        let sid = mission.id;
        let page = "https://x.test/";
        let tech = Finding::new(
            sid,
            FindingKind::Technology,
            None,
            "React (frontend)",
            Confidence::High,
            Provenance::new(Source::Html, Some(page.into())),
        );
        let endpoint = Finding::new(
            sid,
            FindingKind::Endpoint,
            Some("/api/search".into()),
            "GET /api/search",
            Confidence::High,
            Provenance::new(Source::JsAst, Some(page.into())),
        );
        let report = SessionReport::build(
            mission,
            vec![tech, endpoint],
            vec![Endpoint::new(
                "https://x.test/api/search",
                Method::Get,
                Source::JsAst,
            )],
        );
        let graph = report.relation_graph(opts(ReportFormat::Dot));
        let doc = component_key(page);
        let framework = framework_key("React (frontend)");
        let ep = "endpoint:GET https://x.test/api/search".to_owned();
        assert_eq!(graph.nodes[&doc].kind, "document");
        assert_eq!(graph.nodes[&framework].kind, "framework");
        assert!(graph
            .edges
            .contains(&(doc.clone(), framework.clone(), "detected_on")));
        // No transitivity: the technology is never chained onward to an
        // endpoint the same location also reveals.
        assert!(!graph
            .edges
            .iter()
            .any(|(from, to, _)| from == &framework && to == &ep));
        assert!(!graph
            .edges
            .iter()
            .any(|(from, to, _)| from == &ep && to == &framework));
    }
}
