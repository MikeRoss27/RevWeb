// crates/webrev-extract/src/extractors/endpoints/ghost.rs
//! "Ghost endpoint" discovery: reverse the client-side access-control model.
//!
//! Single-page apps routinely hide privileged functionality behind a *client*
//! check — `if (user.isAdmin) { fetch("/admin/users") }`, a feature flag, a
//! role comparison. The guard only decides what the UI renders; the endpoint
//! itself almost always answers server-side regardless of the flag. This
//! extractor walks the JavaScript AST, recognises gate-shaped `if` conditions,
//! and reports the endpoints that appear *inside* the guarded block so they
//! join the discoverable surface (and, under `--active`, get probed) instead of
//! staying invisible to a plain crawl.
//!
//! It is deliberately syntactic and intra-procedural: the gated payload is the
//! block lexically inside the guard, the gate label is the condition's source
//! text matched against a narrow marker list, and recognition is heuristic — a
//! match is a *candidate* worth a look, not a proof. Limitations: no data-flow
//! or aliasing, no cross-function propagation, negated/early-return guards
//! (`if (!isAdmin) return;`) are not modelled, and gated *parameters* (keys
//! added only inside a guard) are left to a future pass.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use swc_core::common::input::StringInput;
use swc_core::common::sync::Lrc;
use swc_core::common::{BytePos, FileName, SourceMap, Spanned};
use swc_core::ecma::ast::{
    CallExpr, Callee, Expr, IfStmt, Lit, MemberExpr, MemberProp, NewExpr, Str,
};
use swc_core::ecma::parser::{EsSyntax, Parser, Syntax};
use swc_core::ecma::visit::{Visit, VisitWith};
use webrev_core::{Confidence, Endpoint, Finding, FindingKind, Method, Provenance, Source};

/// Narrow, case-insensitive markers for a *gate* condition: role / permission /
/// feature-flag vocabulary. Deliberately specific (e.g. `canaccess`, not a bare
/// `can`) so ordinary conditionals like `if (loading)` or `if (canvas)` do not
/// register as access gates.
const GATE_MARKERS: &[&str] = &[
    "isadmin",
    "is_admin",
    "isstaff",
    "is_staff",
    "issuperuser",
    "is_superuser",
    "isinternal",
    "is_internal",
    "role",
    "roles",
    "permission",
    "permissions",
    "hasrole",
    "has_role",
    "haspermission",
    "has_permission",
    "canaccess",
    "can_access",
    "isauthorized",
    "is_authorized",
    "entitlement",
    "entitlements",
    "featureflag",
    "feature_flag",
    "featureflags",
    "flags",
    "isenabled",
    "is_enabled",
    "canary",
    "experiment",
    "privilege",
    "privileges",
];

/// Ghost-endpoint extractor.
pub struct GhostEndpointExtractor;

impl GhostEndpointExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for GhostEndpointExtractor {
    fn default() -> Self {
        Self::new()
    }
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

/// `axios.<method>(...)` → that method.
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

/// `xhr.open(METHOD, url)` → `(method, url)`.
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
    if method == Method::Unknown {
        return None;
    }
    Some((method, nth_string_arg(call, 1)?))
}

/// Collects endpoint targets within one guarded block.
#[derive(Default)]
struct GatedTargets {
    hits: Vec<(Method, String)>,
}

impl Visit for GatedTargets {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        let matched = match &call.callee {
            Callee::Expr(e) => match &**e {
                Expr::Ident(id) if id.sym.as_ref() == "fetch" => Some(Method::Unknown),
                Expr::Member(member) => axios_method(member),
                _ => None,
            },
            Callee::Super(_) | Callee::Import(_) => None,
        };
        if let Some(method) = matched {
            if let Some(url) = nth_string_arg(call, 0) {
                self.hits.push((method, url));
            }
        } else if let Some((method, url)) = xhr_open(call) {
            self.hits.push((method, url));
        }
        call.visit_children_with(self);
    }

    fn visit_new_expr(&mut self, new_expr: &NewExpr) {
        if let Expr::Ident(id) = &*new_expr.callee {
            if matches!(id.sym.as_ref(), "WebSocket" | "EventSource") {
                if let Some(first) = new_expr.args.as_ref().and_then(|args| args.first()) {
                    if let Some(url) = string_literal_value(&first.expr) {
                        self.hits.push((Method::Get, url));
                    }
                }
            }
        }
        new_expr.visit_children_with(self);
    }

    fn visit_str(&mut self, s: &Str) {
        let value = s.value.to_string_lossy();
        if looks_like_endpoint(&value) {
            self.hits.push((Method::Unknown, value.into_owned()));
        }
    }
}

/// A gated endpoint and the client condition that hides it.
struct GhostHit {
    method: Method,
    url: String,
    gate: String,
}

/// Walks the module, collecting gated endpoints. Holds the source text so a
/// gate condition can be rendered as a human-readable label from its span.
struct GhostVisitor<'a> {
    src: &'a str,
    hits: Vec<GhostHit>,
}

impl GhostVisitor<'_> {
    /// The condition's source snippet, trimmed and length-capped, if it reads
    /// as an access/feature gate.
    fn gate_label(&self, test: &Expr) -> Option<String> {
        let span = test.span();
        let lo = span.lo.0 as usize;
        let hi = span.hi.0 as usize;
        let snippet = self.src.get(lo..hi)?.trim();
        let lower = snippet.to_ascii_lowercase();
        if GATE_MARKERS.iter().any(|m| lower.contains(m)) {
            let mut label = snippet.replace(['\n', '\r'], " ");
            if label.len() > 80 {
                // Byte-safe truncation at a char boundary.
                let mut end = 80;
                while !label.is_char_boundary(end) {
                    end -= 1;
                }
                label.truncate(end);
                label.push('…');
            }
            Some(label)
        } else {
            None
        }
    }
}

impl Visit for GhostVisitor<'_> {
    fn visit_if_stmt(&mut self, node: &IfStmt) {
        if let Some(gate) = self.gate_label(&node.test) {
            let mut targets = GatedTargets::default();
            node.cons.visit_with(&mut targets);
            for (method, url) in targets.hits {
                self.hits.push(GhostHit {
                    method,
                    url,
                    gate: gate.clone(),
                });
            }
        }
        // Continue walking: nested gates and siblings still need visiting.
        node.visit_children_with(self);
    }
}

impl Extractor for GhostEndpointExtractor {
    fn name(&self) -> &'static str {
        "ghost"
    }

    fn priority(&self) -> u8 {
        40
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

        let Ok(module) = parser.parse_module() else {
            return Vec::new();
        };

        let mut visitor = GhostVisitor {
            src: &input.body,
            hits: Vec::new(),
        };
        module.visit_with(&mut visitor);

        let mut seen = std::collections::BTreeSet::new();
        let mut findings = Vec::new();
        for hit in visitor.hits {
            let ep = Endpoint::new(hit.url.clone(), hit.method, Source::JsAst);
            // The gated endpoint itself, so it joins the surface. Behind a
            // client gate + inferred rather than observed → Medium.
            let endpoint_value = format!("{} {}", hit.method, hit.url);
            if seen.insert(format!("ep|{endpoint_value}")) {
                let mut f = Finding::from_endpoint(input.session_id, &ep, Confidence::Medium);
                f.provenance = Provenance::new(Source::JsAst, input.url.clone());
                findings.push(f);
            }
            // The insight: which client condition hides it.
            let note = format!(
                "gated endpoint '{}' behind client check: {}",
                hit.url, hit.gate
            );
            if seen.insert(format!("cfg|{note}")) {
                findings.push(Finding::new(
                    input.session_id,
                    FindingKind::Config,
                    None,
                    note,
                    Confidence::Medium,
                    Provenance::new(Source::JsAst, input.url.clone()),
                ));
            }
        }
        findings
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
        GhostEndpointExtractor::new().extract(&input)
    }

    #[test]
    fn reports_endpoint_gated_behind_role_check() {
        let js = r#"
            function render(user) {
                if (user.isAdmin) {
                    fetch("/api/admin/users");
                }
            }
        "#;
        let found = run(js);
        assert!(found.iter().any(
            |f| f.kind == FindingKind::Endpoint && f.url.as_deref() == Some("/api/admin/users")
        ));
        assert!(found.iter().any(|f| f.kind == FindingKind::Config
            && f.value.contains("gated endpoint '/api/admin/users'")
            && f.value.contains("isAdmin")));
    }

    #[test]
    fn reports_endpoint_gated_behind_feature_flag() {
        let js = r#"
            if (flags.betaDashboard) {
                axios.post("/api/v2/dashboard", payload);
            }
        "#;
        let found = run(js);
        assert!(found
            .iter()
            .any(|f| f.kind == FindingKind::Endpoint && f.value == "POST /api/v2/dashboard"));
        assert!(found
            .iter()
            .any(|f| f.kind == FindingKind::Config && f.value.contains("flags.betaDashboard")));
    }

    #[test]
    fn ignores_ordinary_non_gate_conditionals() {
        let js = r#"
            if (isLoading) {
                fetch("/api/public/data");
            }
        "#;
        let found = run(js);
        assert!(
            found.is_empty(),
            "non-gate guard must not report: {found:?}"
        );
    }

    #[test]
    fn dedups_identical_gated_endpoint() {
        let js = r#"
            if (user.role === 'admin') { fetch("/admin/x"); }
            if (user.role === 'admin') { fetch("/admin/x"); }
        "#;
        let found = run(js);
        assert_eq!(
            found
                .iter()
                .filter(|f| f.kind == FindingKind::Endpoint)
                .count(),
            1
        );
    }

    #[test]
    fn unparseable_returns_empty_not_error() {
        assert_eq!(run("function (() {{{ <<< "), Vec::new());
    }
}
