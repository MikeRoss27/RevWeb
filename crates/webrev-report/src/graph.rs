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

#[derive(Default)]
struct RelationGraph {
    nodes: BTreeMap<String, Node>,
    edges: BTreeSet<(String, String, &'static str)>,
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
        self.nodes.entry(key).or_insert(Node {
            kind,
            label,
            scope,
            confidence,
        });
    }

    fn edge(&mut self, from: String, to: String, relation: &'static str) {
        self.edges.insert((from, to, relation));
    }
}

fn endpoint_key(endpoint: &Endpoint) -> String {
    format!("endpoint:{} {}", endpoint.method, endpoint.url)
}

fn component_key(location: &str) -> String {
    format!("component:{location}")
}

fn parameter_key(name: &str) -> String {
    format!("parameter:{name}")
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
                        for location in source_locations(finding) {
                            let component = component_key(location);
                            graph.node(
                                component.clone(),
                                "component",
                                location.to_owned(),
                                None,
                                None,
                            );
                            graph.edge(component, ep_key.clone(), "reveals");
                        }
                    }
                }
                FindingKind::Parameter => {
                    let name = finding.value.trim();
                    if name.is_empty() {
                        continue;
                    }
                    let parameter = parameter_key(name);
                    graph.node(parameter.clone(), "parameter", name.to_owned(), None, None);
                    for location in source_locations(finding) {
                        let component = component_key(location);
                        graph.node(
                            component.clone(),
                            "component",
                            location.to_owned(),
                            None,
                            None,
                        );
                        graph.edge(component, parameter.clone(), "mentions_parameter");
                    }
                    if let Some(endpoint) = matching_endpoint(finding, &endpoints) {
                        graph.edge(endpoint_key(endpoint), parameter, "has_parameter");
                    }
                }
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
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<graphml xmlns=\"http://graphml.graphdrawing.org/xmlns\">\n  <key id=\"kind\" for=\"node\" attr.name=\"kind\" attr.type=\"string\"/>\n  <key id=\"label\" for=\"node\" attr.name=\"label\" attr.type=\"string\"/>\n  <key id=\"scope\" for=\"node\" attr.name=\"scope\" attr.type=\"string\"/>\n  <key id=\"confidence\" for=\"node\" attr.name=\"confidence\" attr.type=\"int\"/>\n  <key id=\"relation\" for=\"edge\" attr.name=\"relation\" attr.type=\"string\"/>\n  <graph id=\"webrev\" edgedefault=\"directed\">\n");
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
}
