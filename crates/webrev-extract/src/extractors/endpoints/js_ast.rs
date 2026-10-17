// crates/webrev-extract/src/extractors/endpoints/js_ast.rs
//! Precise endpoint extraction by walking the JavaScript AST with `swc`.
//!
//! Unlike the regex extractor this understands call structure, so it can
//! attribute a method to `axios.post("…")` reliably and only reports string
//! literals that are genuinely endpoint-shaped. Minified or syntactically
//! exotic code that fails to parse falls through to the regex extractor.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use std::collections::BTreeSet;
use swc_core::common::input::StringInput;
use swc_core::common::sync::Lrc;
use swc_core::common::{BytePos, FileName, SourceMap};
use swc_core::ecma::ast::{CallExpr, Callee, Expr, Lit, MemberExpr, MemberProp, NewExpr, Str};
use swc_core::ecma::parser::{EsSyntax, Parser, Syntax};
use swc_core::ecma::visit::{Visit, VisitWith};
use webrev_core::{Confidence, Endpoint, Finding, FindingKind, Method, Provenance, Source};

/// AST-based JavaScript endpoint extractor.
pub struct JsAstExtractor;

impl JsAstExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsAstExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// Collects endpoints while walking the tree.
#[derive(Default)]
struct EndpointVisitor {
    hits: Vec<(Endpoint, Confidence)>,
    candidate_strings: Vec<String>,
    /// Module specifiers passed to a dynamic `import(...)`. Reported
    /// separately (as [`webrev_core::FindingKind::Script`], not an
    /// [`Endpoint`]): a lazy-loaded chunk like `import("./AdminPanel")` is a
    /// module path, not a request target, but it reveals a route the bundler
    /// never surfaces in a plain HTML/script crawl.
    dynamic_imports: Vec<String>,
}

fn string_literal_value(expr: &Expr) -> Option<String> {
    if let Expr::Lit(Lit::Str(Str { value, .. })) = expr {
        Some(value.to_string_lossy().into_owned())
    } else {
        None
    }
}

fn nth_string_arg(call: &CallExpr, idx: usize) -> Option<String> {
    let arg = call.args.get(idx)?;
    if arg.spread.is_some() {
        return None;
    }
    string_literal_value(&arg.expr)
}

/// Return a static string or a template literal with interpolations represented
/// as `{}`. Keeping the marker makes the discovered route useful without
/// pretending that a runtime value is known.
fn static_url_arg(call: &CallExpr, idx: usize) -> Option<String> {
    let arg = call.args.get(idx)?;
    if arg.spread.is_some() {
        return None;
    }
    match &*arg.expr {
        Expr::Lit(Lit::Str(_)) => string_literal_value(&arg.expr),
        Expr::Tpl(template) => {
            let mut url = String::new();
            for (index, quasi) in template.quasis.iter().enumerate() {
                url.push_str(quasi.cooked.as_ref()?.to_string_lossy().as_ref());
                if index < template.exprs.len() {
                    url.push_str("{}");
                }
            }
            // Angular applications commonly interpolate a configured origin
            // before a stable route (`${this.apiBase}/rest/items`). Keep the
            // route while omitting that unknown host expression.
            if url.starts_with("{}") && url[2..].starts_with('/') {
                url.drain(..2);
            }
            looks_like_endpoint(&url).then_some(url)
        }
        _ => None,
    }
}

/// Recognize Angular `HttpClient` calls such as `this.http.get(url)` and
/// `http.post(url, body)`. Requiring the receiver to be named `http` avoids
/// treating arbitrary `.get()` methods as network activity.
fn http_client_method(member: &MemberExpr) -> Option<Method> {
    fn path(expr: &Expr) -> Option<String> {
        match expr {
            Expr::Ident(id) => Some(id.sym.as_ref().to_owned()),
            Expr::This(_) => Some("this".to_owned()),
            Expr::Member(member) => {
                let MemberProp::Ident(prop) = &member.prop else {
                    return None;
                };
                Some(format!("{}.{}", path(&member.obj)?, prop.sym))
            }
            _ => None,
        }
    }

    let MemberProp::Ident(prop) = &member.prop else {
        return None;
    };
    let method = match prop.sym.as_ref() {
        "get" => Method::Get,
        "post" => Method::Post,
        "put" => Method::Put,
        "delete" => Method::Delete,
        "patch" => Method::Patch,
        _ => return None,
    };
    let receiver = path(&member.obj)?;
    receiver
        .split('.')
        .next_back()
        .filter(|name| *name == "http")
        .map(|_| method)
}

/// Detect `xhr.open(METHOD, url)` calls, returning `(method, url)`.
fn xhr_open(call: &CallExpr) -> Option<(Method, String)> {
    let Callee::Expr(callee) = &call.callee else {
        return None;
    };
    let Expr::Member(member) = &**callee else {
        return None;
    };
    let MemberProp::Ident(prop) = &member.prop else {
        return None;
    };
    if prop.sym.as_ref() != "open" {
        return None;
    }
    let method = Method::parse(&nth_string_arg(call, 0)?);
    // Only accept a recognised verb to avoid matching unrelated `.open(...)`.
    if method == Method::Unknown {
        return None;
    }
    Some((method, nth_string_arg(call, 1)?))
}

/// If the member expression is `axios.<method>`, return that method.
fn axios_method(member: &MemberExpr) -> Option<Method> {
    let Expr::Ident(obj) = &*member.obj else {
        return None;
    };
    if obj.sym.as_ref() != "axios" {
        return None;
    }
    let MemberProp::Ident(prop) = &member.prop else {
        return None;
    };
    match prop.sym.as_ref() {
        m @ ("get" | "post" | "put" | "delete" | "patch") => Some(Method::parse(m)),
        _ => None,
    }
}

fn looks_like_endpoint(s: &str) -> bool {
    if s.contains(char::is_whitespace) {
        return false;
    }
    s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("ws://")
        || s.starts_with("wss://")
        || (s.starts_with('/') && !s.starts_with("//") && s.len() > 1)
}

impl Visit for EndpointVisitor {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        let matched = match &call.callee {
            Callee::Expr(e) => match &**e {
                Expr::Ident(id) if id.sym.as_ref() == "fetch" => Some(Method::Unknown),
                Expr::Member(member) => axios_method(member).or_else(|| http_client_method(member)),
                _ => None,
            },
            Callee::Super(_) | Callee::Import(_) => None,
        };
        if let Some(method) = matched {
            if let Some(url) = static_url_arg(call, 0) {
                self.hits
                    .push((Endpoint::new(url, method, Source::JsAst), Confidence::High));
            }
        } else if let Some((method, url)) = xhr_open(call) {
            self.hits
                .push((Endpoint::new(url, method, Source::JsAst), Confidence::High));
        } else if let Callee::Import(_) = call.callee {
            if let Some(spec) = nth_string_arg(call, 0) {
                self.dynamic_imports.push(spec);
            }
        }
        call.visit_children_with(self);
    }

    fn visit_new_expr(&mut self, new_expr: &NewExpr) {
        // `new WebSocket(url)` / `new EventSource(url)`.
        if let Expr::Ident(id) = &*new_expr.callee {
            if matches!(id.sym.as_ref(), "WebSocket" | "EventSource") {
                if let Some(first) = new_expr.args.as_ref().and_then(|args| args.first()) {
                    if let Some(url) = string_literal_value(&first.expr) {
                        self.hits.push((
                            Endpoint::new(url, Method::Get, Source::JsAst),
                            Confidence::High,
                        ));
                    }
                }
            }
        }
        new_expr.visit_children_with(self);
    }

    fn visit_str(&mut self, s: &Str) {
        let value = s.value.to_string_lossy();
        if looks_like_endpoint(&value) {
            self.candidate_strings.push(value.into_owned());
        }
    }
}

impl Extractor for JsAstExtractor {
    fn name(&self) -> &'static str {
        "js-ast"
    }

    fn priority(&self) -> u8 {
        90
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        input.kind == ContentKind::JavaScript
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let cm: Lrc<SourceMap> = Lrc::default();
        let fm = cm.new_source_file(Lrc::new(FileName::Anon), input.body.clone());
        let len = u32::try_from(fm.src.len()).unwrap_or(u32::MAX);
        let parser_input = StringInput::new(&fm.src, BytePos(0), BytePos(len));
        let mut parser = Parser::new(Syntax::Es(EsSyntax::default()), parser_input, None);

        // Unparseable input (e.g. TypeScript or exotic syntax) is not an error
        // here: the regex extractor is the fallback for such files.
        let Ok(module) = parser.parse_module() else {
            return Vec::new();
        };

        let mut visitor = EndpointVisitor::default();
        module.visit_with(&mut visitor);

        let called: BTreeSet<String> = visitor.hits.iter().map(|(ep, _)| ep.url.clone()).collect();

        let endpoints = visitor.hits.into_iter().map(|(ep, confidence)| {
            let mut f = Finding::from_endpoint(input.session_id, &ep, confidence);
            f.provenance = Provenance::new(Source::JsAst, input.url.clone());
            f
        });
        let imports = visitor.dynamic_imports.into_iter().map(|spec| {
            Finding::new(
                input.session_id,
                FindingKind::Script,
                None,
                spec,
                Confidence::Medium,
                Provenance::new(Source::JsAst, input.url.clone()),
            )
        });
        let candidates = visitor
            .candidate_strings
            .into_iter()
            .filter(move |s| !called.contains(s))
            .map(|s| {
                Finding::new(
                    input.session_id,
                    FindingKind::Config,
                    None,
                    format!("network URL candidate (static string): {s}"),
                    Confidence::Low,
                    Provenance::new(Source::JsAst, input.url.clone()),
                )
            });
        endpoints.chain(imports).chain(candidates).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    fn run(js: &str) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/app.js".into()),
            ContentKind::JavaScript,
            js,
        );
        JsAstExtractor::new().extract(&input)
    }

    #[test]
    fn extracts_fetch_and_axios_with_method() {
        let js = r#"
            async function load() {
                const a = await fetch("/api/profile");
                await axios.post("/api/login", creds);
                const noise = "not a url with spaces";
            }
        "#;
        let found = run(js);
        assert!(found
            .iter()
            .any(|f| f.url.as_deref() == Some("/api/profile")));
        assert!(found
            .iter()
            .any(|f| f.value == "POST /api/login" && f.confidence == Confidence::High));
        // The spaced string is not endpoint-shaped.
        assert!(found
            .iter()
            .all(|f| f.url.as_deref() != Some("not a url with spaces")));
    }

    #[test]
    fn extracts_angular_httpclient_template_url_with_static_route() {
        let found = run(
            "function load() { return this.http.get(`${this.hostServer}/rest/products/search?q=${criteria}`); }",
        );
        assert!(
            found.iter().any(|finding| {
                finding.kind == FindingKind::Endpoint
                    && finding.value == "GET /rest/products/search?q={}"
                    && finding.confidence == Confidence::High
            }),
            "findings: {found:?}"
        );
    }

    #[test]
    fn extracts_xhr_open_and_websocket() {
        let js = r#"
            const x = new XMLHttpRequest();
            x.open("GET", "/api/xhr");
            const s = new WebSocket("wss://t/ws");
        "#;
        let found = run(js);
        assert!(found.iter().any(|f| f.value == "GET /api/xhr"));
        assert!(found.iter().any(|f| f.url.as_deref() == Some("wss://t/ws")));
    }

    #[test]
    fn extracts_dynamic_import_specifiers() {
        let js = r#"
            async function loadAdmin() {
                const mod = await import("./AdminPanel");
                return mod;
            }
        "#;
        let found = run(js);
        assert!(found
            .iter()
            .any(|f| f.kind == FindingKind::Script && f.value == "./AdminPanel"));
    }

    #[test]
    fn unparseable_returns_empty_not_error() {
        // A stray token that fails ES parsing.
        let found = run("function (() {{{ <<< ");
        assert_eq!(found, Vec::new());
    }
}
