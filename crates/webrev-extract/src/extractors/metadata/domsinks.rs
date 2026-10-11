// crates/webrev-extract/src/extractors/metadata/domsinks.rs
//! Flags client-side DOM-XSS exposure in JavaScript, with evidence of a
//! *dataflow path* from an attacker-controllable source into a dangerous sink
//! rather than the mere presence of a sink.
//!
//! # Two passes
//!
//! 1. **Static taint pass (swc AST, [`Source::JsAst`]).** A lightweight,
//!    *intra-procedural* taint tracker walks the module and reports flows of
//!    the form `source -> sink` (e.g. `DOM XSS: location.hash -> el.innerHTML`).
//!    A flow is reported when a sink's argument / right-hand side is:
//!    (a) directly a taint source, (b) a variable previously assigned a tainted
//!    value in an enclosing scope, or (c) a string concatenation / template
//!    literal containing a tainted value. Direct source → sink flows are
//!    `High` confidence; flows laundered through a variable or a
//!    concatenation are `Medium`.
//!    - **Sources:** `location`, `location.href`/`search`/`hash`/`pathname`,
//!      `document.URL`/`documentURI`/`referrer`/`cookie`/`baseURI`,
//!      `window.name`, and, inside a `message` event handler, the handler's
//!      first parameter and its `.data` property (`event.data` / `e.data`).
//!    - **Sinks:** assignment to `.innerHTML`/`.outerHTML`, `document.write(`
//!      / `writeln(`, `eval(`, `new Function(`, `.insertAdjacentHTML(`,
//!      assignment to `location` / `location.href`, and the React
//!      `dangerouslySetInnerHTML` `{__html: …}` property.
//!
//! 2. **Regex fallback ([`Source::JsRegex`]).** To keep recall on minified or
//!    unparseable code, every sink *pattern* is still matched textually; a sink
//!    for which the taint pass traced no source is emitted as a `Low`
//!    "unverified source" lead (unless it falls inside a traced flow, in which
//!    case the higher-confidence AST finding already covers it). `WebAssembly.*`
//!    / `*.wasm` references and `postMessage` receiver origin-check analysis are
//!    retained here unchanged.
//!
//! # Limitations (deliberately conservative — these are leads, not proofs)
//!
//! The taint model is intra-procedural and single-file: there is **no**
//! cross-function propagation (a tainted value passed as an argument is not
//! tracked into the callee) and **no** aliasing analysis beyond simple
//! `x = <tainted>` assignments (no object-field, array-element, or destructuring
//! tracking). A tainted value's property access / method call is conservatively
//! assumed to stay tainted (`location.hash.slice(1)` is still tainted). Scope
//! lookup is lexical but generous: an inner closure can see an outer scope's
//! tainted variables. Sanitizers (`DOMPurify.sanitize`, framework escaping) are
//! not modelled, so a traced flow is a *candidate*, not a confirmed bug.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use swc_core::common::input::StringInput;
use swc_core::common::sync::Lrc;
use swc_core::common::{BytePos, FileName, SourceMap, Spanned};
use swc_core::ecma::ast::{
    ArrowExpr, AssignExpr, AssignOp, AssignTarget, BinaryOp, CallExpr, Callee, Expr, ExprOrSpread,
    Function, KeyValueProp, Lit, MemberExpr, MemberProp, NewExpr, Pat, PropName,
    SimpleAssignTarget, VarDeclarator,
};
use swc_core::ecma::parser::{EsSyntax, Parser, Syntax};
use swc_core::ecma::visit::{Visit, VisitWith};
use webrev_core::{Confidence, Finding, FindingKind, Provenance, SessionId, Source};

/// Generic sink patterns for the regex fallback: `(regex, label)`. All are
/// emitted at `Low` confidence as "unverified source" leads unless the taint
/// pass already traced a source into them.
const FALLBACK_SINK_PATTERNS: &[(&str, &str)] = &[
    (
        r"(?i)\.innerhtml\s*=[^=]",
        "innerHTML assignment (DOM-XSS sink)",
    ),
    (
        r"(?i)\.outerhtml\s*=[^=]",
        "outerHTML assignment (DOM-XSS sink)",
    ),
    (r"(?i)document\.write(?:ln)?\s*\(", "document.write() sink"),
    (r"\beval\s*\(", "eval() sink"),
    (
        r"(?i)\.insertadjacenthtml\s*\(",
        "insertAdjacentHTML() sink",
    ),
    (r"\bnew\s+Function\s*\(", "new Function() sink"),
    (
        r"dangerouslySetInnerHTML",
        "React dangerouslySetInnerHTML sink",
    ),
    (
        r"(?i)location\.href\s*=[^=]",
        "location.href assignment (navigation sink)",
    ),
];

/// WebAssembly reference patterns, reported as-is at `Low`.
const WASM_PATTERNS: &[(&str, &str)] = &[
    (
        r"(?i)WebAssembly\.(?:instantiatestreaming|instantiate|compilestreaming|compile)",
        "WebAssembly instantiation",
    ),
    (r"(?i)[\w./\-]+\.wasm\b", "WebAssembly module reference"),
];

/// `postMessage` receiver patterns, analysed specially for a nearby origin
/// check.
const MESSAGE_PATTERNS: &[&str] = &[
    r#"(?i)addeventlistener\s*\(\s*['"]message['"]"#,
    r"(?i)\bonmessage\s*=[^=]",
];

/// Functions that preserve taint on their (string) argument.
const TAINT_PRESERVING_CALLS: &[&str] = &[
    "decodeURIComponent",
    "decodeURI",
    "encodeURIComponent",
    "unescape",
    "escape",
    "String",
    "atob",
];

/// How far past a `message` handler to look for an `origin` check.
const ORIGIN_WINDOW: usize = 240;

/// DOM-sink taint / postMessage / wasm extractor.
pub struct DomSinkExtractor {
    sink_patterns: Vec<(Regex, &'static str)>,
    wasm_patterns: Vec<(Regex, &'static str)>,
    message: Vec<Regex>,
}

impl DomSinkExtractor {
    /// Build the extractor.
    ///
    /// # Panics
    ///
    /// Never at runtime: all patterns are constants verified by the
    /// `patterns_compile` unit test.
    #[must_use]
    pub fn new() -> Self {
        let sink_patterns = FALLBACK_SINK_PATTERNS
            .iter()
            .map(|(re, label)| (Regex::new(re).expect("sink pattern is valid"), *label))
            .collect();
        let wasm_patterns = WASM_PATTERNS
            .iter()
            .map(|(re, label)| (Regex::new(re).expect("wasm pattern is valid"), *label))
            .collect();
        let message = MESSAGE_PATTERNS
            .iter()
            .map(|re| Regex::new(re).expect("message pattern is valid"))
            .collect();
        Self {
            sink_patterns,
            wasm_patterns,
            message,
        }
    }
}

impl Default for DomSinkExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// A whitespace-collapsed snippet of source starting at `start`, bounded to the
/// current statement (stops at the first `;` or newline, or 96 chars). Bounding
/// to the statement keeps repeated identical sinks deduplicating cleanly.
fn snippet(body: &str, start: usize) -> String {
    let window: String = body[start..]
        .chars()
        .take(96)
        .take_while(|&c| c != ';' && c != '\n')
        .collect();
    window.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Build a dotted path for an identifier / plain member chain, e.g.
/// `window.location.hash`. Returns `None` for computed / call / exotic objects.
fn member_path(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident(id) => Some(id.sym.as_ref().to_owned()),
        Expr::Paren(p) => member_path(&p.expr),
        Expr::Member(m) => member_expr_path(m),
        _ => None,
    }
}

fn member_expr_path(m: &MemberExpr) -> Option<String> {
    let obj = member_path(&m.obj)?;
    let MemberProp::Ident(prop) = &m.prop else {
        return None;
    };
    Some(format!("{obj}.{}", prop.sym.as_ref()))
}

fn member_prop_name(m: &MemberExpr) -> Option<String> {
    if let MemberProp::Ident(prop) = &m.prop {
        Some(prop.sym.as_ref().to_owned())
    } else {
        None
    }
}

/// Map a member/identifier path to a canonical taint-source label, or `None`.
fn known_source(path: &str) -> Option<String> {
    let tail = path
        .strip_prefix("window.")
        .or_else(|| path.strip_prefix("self."))
        .unwrap_or(path);
    let had_prefix = tail.len() != path.len();
    match tail {
        "location" => Some("location".to_owned()),
        "location.href" | "location.search" | "location.hash" | "location.pathname" => {
            Some(tail.to_owned())
        }
        "document.URL"
        | "document.documentURI"
        | "document.referrer"
        | "document.cookie"
        | "document.baseURI" => Some(tail.to_owned()),
        "name" if had_prefix => Some("window.name".to_owned()),
        _ => None,
    }
}

/// Canonical sink label for an assignment to a navigation target, or `None`.
fn nav_sink(path: &str) -> Option<&'static str> {
    let tail = path
        .strip_prefix("window.")
        .or_else(|| path.strip_prefix("self."))
        .unwrap_or(path);
    match tail {
        "location" => Some("location"),
        "location.href" => Some("location.href"),
        _ => None,
    }
}

fn pat_ident_name(pat: &Pat) -> Option<String> {
    if let Pat::Ident(bi) = pat {
        Some(bi.id.sym.as_ref().to_owned())
    } else {
        None
    }
}

/// Span of a function/arrow literal (unwrapping parentheses), as a byte range.
fn fn_or_arrow_span(expr: &Expr) -> Option<(usize, usize)> {
    match expr {
        Expr::Fn(f) => Some(span_tuple(f.function.span())),
        Expr::Arrow(a) => Some(span_tuple(a.span())),
        Expr::Paren(p) => fn_or_arrow_span(&p.expr),
        _ => None,
    }
}

fn span_tuple(span: swc_core::common::Span) -> (usize, usize) {
    (span.lo.0 as usize, span.hi.0 as usize)
}

/// A value found to carry taint: `(origin label, direct)`. `direct` is true
/// only when the value *is* a source expression (not laundered through a
/// variable or a concatenation), which drives `High` vs `Medium` confidence.
type Taint = (String, bool);

/// Intra-procedural taint tracker. Scopes are a stack of
/// `variable name -> taint origin`; `message` handler parameters are seeded as
/// tainted on scope entry.
struct TaintVisitor {
    scopes: Vec<BTreeMap<String, String>>,
    /// Byte-range spans of function/arrow literals that are `message` handlers,
    /// so their first parameter can be seeded as tainted.
    handler_spans: BTreeSet<(usize, usize)>,
    /// Traced `source -> sink` flows as `(value, confidence)`.
    traces: Vec<(String, Confidence)>,
    /// Byte-range spans of statements/expressions that carried a traced flow,
    /// used to suppress the redundant regex "unverified source" lead.
    traced_spans: Vec<(usize, usize)>,
}

impl TaintVisitor {
    fn new() -> Self {
        Self {
            scopes: vec![BTreeMap::new()],
            handler_spans: BTreeSet::new(),
            traces: Vec::new(),
            traced_spans: Vec::new(),
        }
    }

    fn lookup(&self, name: &str) -> Option<String> {
        self.scopes.iter().rev().find_map(|s| s.get(name).cloned())
    }

    fn insert_var(&mut self, name: String, origin: String) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(name, origin);
        }
    }

    fn clear_var(&mut self, name: &str) {
        for scope in self.scopes.iter_mut().rev() {
            if scope.remove(name).is_some() {
                return;
            }
        }
    }

    /// Classify an expression's taint, following the three flow rules.
    fn classify(&self, expr: &Expr) -> Option<Taint> {
        match expr {
            Expr::Paren(p) => self.classify(&p.expr),
            Expr::Ident(id) => {
                let name = id.sym.as_ref();
                if let Some(origin) = self.lookup(name) {
                    Some((origin, false))
                } else if name == "location" {
                    Some(("location".to_owned(), true))
                } else {
                    None
                }
            }
            Expr::Member(m) => {
                if let Some(path) = member_expr_path(m) {
                    if let Some(label) = known_source(&path) {
                        return Some((label, true));
                    }
                }
                // Property of a tainted value stays tainted (conservative).
                self.classify(&m.obj)
            }
            Expr::Call(call) => self.classify_call(call),
            Expr::Bin(bin) if bin.op == BinaryOp::Add => self
                .classify(&bin.left)
                .or_else(|| self.classify(&bin.right))
                .map(|(origin, _)| (origin, false)),
            Expr::Tpl(tpl) => tpl
                .exprs
                .iter()
                .find_map(|e| self.classify(e))
                .map(|(origin, _)| (origin, false)),
            _ => None,
        }
    }

    fn classify_call(&self, call: &CallExpr) -> Option<Taint> {
        let Callee::Expr(callee) = &call.callee else {
            return None;
        };
        match &**callee {
            // `tainted.method(...)` (string methods preserve taint).
            Expr::Member(m) => self.classify(&m.obj),
            // `decodeURIComponent(tainted)` and friends.
            Expr::Ident(id) if TAINT_PRESERVING_CALLS.contains(&id.sym.as_ref()) => {
                self.first_tainted_arg(&call.args)
            }
            _ => None,
        }
    }

    fn first_tainted_arg(&self, args: &[ExprOrSpread]) -> Option<Taint> {
        args.iter()
            .filter(|a| a.spread.is_none())
            .find_map(|a| self.classify(&a.expr))
    }

    /// Record a traced `source -> sink` flow and the span it covers.
    fn trace(&mut self, (origin, direct): Taint, sink: &str, span: swc_core::common::Span) {
        let confidence = if direct {
            Confidence::High
        } else {
            Confidence::Medium
        };
        self.traces
            .push((format!("DOM XSS: {origin} -> {sink}"), confidence));
        self.traced_spans.push(span_tuple(span));
    }

    /// Seed the first parameter of a `message` handler as tainted.
    fn seed_handler_param(&mut self, first_param: Option<String>, is_handler: bool) {
        if is_handler {
            if let Some(name) = first_param {
                self.insert_var(name, "event.data".to_owned());
            }
        }
    }

    /// Handle the sink/registration logic of an assignment (`=` only).
    fn assign_sink(&mut self, assign: &AssignExpr) {
        if assign.op != AssignOp::Assign {
            return;
        }
        match &assign.left {
            AssignTarget::Simple(SimpleAssignTarget::Member(m)) => {
                let Some(prop) = member_prop_name(m) else {
                    return;
                };
                let lower = prop.to_ascii_lowercase();
                if lower == "innerhtml" || lower == "outerhtml" {
                    if let Some(taint) = self.classify(&assign.right) {
                        let sink = member_expr_path(m).unwrap_or_else(|| format!("(expr).{prop}"));
                        self.trace(taint, &sink, assign.span());
                    }
                } else if let Some(sink) = member_expr_path(m).as_deref().and_then(nav_sink) {
                    if let Some(taint) = self.classify(&assign.right) {
                        self.trace(taint, sink, assign.span());
                    }
                }
            }
            AssignTarget::Simple(SimpleAssignTarget::Ident(bi))
                if bi.id.sym.as_ref() == "location" =>
            {
                if let Some(taint) = self.classify(&assign.right) {
                    self.trace(taint, "location", assign.span());
                }
            }
            _ => {}
        }
    }

    /// Track a simple `x = <tainted>` assignment in the current scope.
    fn assign_var(&mut self, assign: &AssignExpr) {
        if assign.op != AssignOp::Assign {
            return;
        }
        let AssignTarget::Simple(SimpleAssignTarget::Ident(bi)) = &assign.left else {
            return;
        };
        let name = bi.id.sym.as_ref();
        if name == "location" {
            return;
        }
        let name = name.to_owned();
        match self.classify(&assign.right) {
            Some((origin, _)) => self.insert_var(name, origin),
            None => self.clear_var(&name),
        }
    }

    /// Register a `message` handler assigned via `onmessage = fn`.
    fn register_onmessage(&mut self, assign: &AssignExpr) {
        let is_onmessage = match &assign.left {
            AssignTarget::Simple(SimpleAssignTarget::Member(m)) => {
                member_prop_name(m).as_deref() == Some("onmessage")
            }
            AssignTarget::Simple(SimpleAssignTarget::Ident(bi)) => {
                bi.id.sym.as_ref() == "onmessage"
            }
            _ => false,
        };
        if is_onmessage {
            if let Some(span) = fn_or_arrow_span(&assign.right) {
                self.handler_spans.insert(span);
            }
        }
    }

    /// Register a `message` handler passed to `addEventListener('message', fn)`.
    fn register_addeventlistener(&mut self, call: &CallExpr) {
        let Callee::Expr(callee) = &call.callee else {
            return;
        };
        let Expr::Member(m) = &**callee else {
            return;
        };
        if member_prop_name(m).as_deref() != Some("addEventListener") {
            return;
        }
        let Some(first) = call.args.first() else {
            return;
        };
        if first.spread.is_some() {
            return;
        }
        let Expr::Lit(Lit::Str(s)) = &*first.expr else {
            return;
        };
        if &*s.value.to_string_lossy() != "message" {
            return;
        }
        if let Some(handler) = call.args.get(1) {
            if let Some(span) = fn_or_arrow_span(&handler.expr) {
                self.handler_spans.insert(span);
            }
        }
    }

    /// Handle the sink logic of a call expression.
    fn call_sink(&mut self, call: &CallExpr) {
        let Callee::Expr(callee) = &call.callee else {
            return;
        };
        match &**callee {
            Expr::Ident(id) if id.sym.as_ref() == "eval" => {
                if let Some(taint) = self.first_tainted_arg(&call.args) {
                    self.trace(taint, "eval", call.span());
                }
            }
            Expr::Member(m) => self.member_call_sink(call, m),
            _ => {}
        }
    }

    fn member_call_sink(&mut self, call: &CallExpr, m: &MemberExpr) {
        let Some(prop) = member_prop_name(m) else {
            return;
        };
        let lower = prop.to_ascii_lowercase();
        if (lower == "write" || lower == "writeln") && object_is_document(m) {
            if let Some(taint) = self.first_tainted_arg(&call.args) {
                self.trace(taint, &format!("document.{prop}"), call.span());
            }
        } else if lower == "insertadjacenthtml" {
            if let Some(taint) = self.first_tainted_arg(&call.args) {
                let sink = member_expr_path(m).unwrap_or_else(|| "insertAdjacentHTML".to_owned());
                self.trace(taint, &sink, call.span());
            }
        }
    }
}

fn object_is_document(m: &MemberExpr) -> bool {
    member_path(&m.obj).is_some_and(|path| {
        let tail = path
            .strip_prefix("window.")
            .or_else(|| path.strip_prefix("self."))
            .unwrap_or(&path);
        tail == "document"
    })
}

impl Visit for TaintVisitor {
    fn visit_assign_expr(&mut self, assign: &AssignExpr) {
        self.assign_sink(assign);
        self.register_onmessage(assign);
        self.assign_var(assign);
        assign.visit_children_with(self);
    }

    fn visit_call_expr(&mut self, call: &CallExpr) {
        // Register handlers before descending so the handler body sees its
        // parameter as tainted.
        self.register_addeventlistener(call);
        self.call_sink(call);
        call.visit_children_with(self);
    }

    fn visit_new_expr(&mut self, new_expr: &NewExpr) {
        if let Expr::Ident(id) = &*new_expr.callee {
            if id.sym.as_ref() == "Function" {
                if let Some(taint) = new_expr
                    .args
                    .as_deref()
                    .and_then(|args| self.first_tainted_arg(args))
                {
                    self.trace(taint, "new Function", new_expr.span());
                }
            }
        }
        new_expr.visit_children_with(self);
    }

    fn visit_var_declarator(&mut self, decl: &VarDeclarator) {
        if let Pat::Ident(bi) = &decl.name {
            if let Some(init) = &decl.init {
                if let Some((origin, _)) = self.classify(init) {
                    self.insert_var(bi.id.sym.as_ref().to_owned(), origin);
                }
            }
        }
        decl.visit_children_with(self);
    }

    fn visit_key_value_prop(&mut self, prop: &KeyValueProp) {
        let key = match &prop.key {
            PropName::Ident(id) => Some(id.sym.as_ref().to_owned()),
            PropName::Str(s) => Some(s.value.to_string_lossy().into_owned()),
            _ => None,
        };
        if key.as_deref() == Some("__html") {
            if let Some(taint) = self.classify(&prop.value) {
                self.trace(taint, "dangerouslySetInnerHTML", prop.value.span());
            }
        }
        prop.value.visit_children_with(self);
    }

    fn visit_function(&mut self, f: &Function) {
        let is_handler = self.handler_spans.contains(&span_tuple(f.span()));
        self.scopes.push(BTreeMap::new());
        let first_param = f.params.first().and_then(|p| pat_ident_name(&p.pat));
        self.seed_handler_param(first_param, is_handler);
        f.visit_children_with(self);
        self.scopes.pop();
    }

    fn visit_arrow_expr(&mut self, a: &ArrowExpr) {
        let is_handler = self.handler_spans.contains(&span_tuple(a.span()));
        self.scopes.push(BTreeMap::new());
        let first_param = a.params.first().and_then(pat_ident_name);
        self.seed_handler_param(first_param, is_handler);
        a.visit_children_with(self);
        self.scopes.pop();
    }
}

/// Traced `source -> sink` flows and the byte-range spans they cover.
type TaintResult = (Vec<(String, Confidence)>, Vec<(usize, usize)>);

/// Run the AST taint pass, returning traced flows and their covering spans.
/// Returns empty (never errors) on parse failure, mirroring the other AST
/// extractors.
fn run_taint(body: &str) -> TaintResult {
    let cm: Lrc<SourceMap> = Lrc::default();
    let fm = cm.new_source_file(Lrc::new(FileName::Anon), body.to_owned());
    let len = u32::try_from(fm.src.len()).unwrap_or(u32::MAX);
    let parser_input = StringInput::new(&fm.src, BytePos(0), BytePos(len));
    // JSX is enabled so React (`dangerouslySetInnerHTML`) parses.
    let syntax = Syntax::Es(EsSyntax {
        jsx: true,
        ..EsSyntax::default()
    });
    let mut parser = Parser::new(syntax, parser_input, None);

    let Ok(module) = parser.parse_module() else {
        return (Vec::new(), Vec::new());
    };

    let mut visitor = TaintVisitor::new();
    module.visit_with(&mut visitor);
    (visitor.traces, visitor.traced_spans)
}

/// Push a finding iff its value has not been seen, keeping dedup on `value`.
fn push_unique(
    findings: &mut Vec<Finding>,
    seen: &mut BTreeSet<String>,
    session: SessionId,
    url: Option<&str>,
    value: String,
    confidence: Confidence,
    source: Source,
) {
    if seen.insert(value.clone()) {
        findings.push(Finding::new(
            session,
            FindingKind::Config,
            None,
            value,
            confidence,
            Provenance::new(source, url.map(str::to_owned)),
        ));
    }
}

impl Extractor for DomSinkExtractor {
    fn name(&self) -> &'static str {
        "dom-sinks"
    }

    fn priority(&self) -> u8 {
        42
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        input.kind == ContentKind::JavaScript
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let body = &input.body;
        let session = input.session_id;
        let url = input.url.as_deref();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut findings = Vec::new();

        // Pass 1: static taint flows (AST).
        let (traces, traced_spans) = run_taint(body);
        for (value, confidence) in traces {
            push_unique(
                &mut findings,
                &mut seen,
                session,
                url,
                value,
                confidence,
                Source::JsAst,
            );
        }

        // Pass 2: regex fallback. Sink leads whose statement was already traced
        // are suppressed; everything else is a Low "unverified source" lead.
        for (regex, label) in &self.sink_patterns {
            for m in regex.find_iter(body) {
                let start = m.start();
                if traced_spans
                    .iter()
                    .any(|&(lo, hi)| lo <= start && start < hi)
                {
                    continue;
                }
                push_unique(
                    &mut findings,
                    &mut seen,
                    session,
                    url,
                    format!(
                        "dom sink (unverified source): {label}: {}",
                        snippet(body, start)
                    ),
                    Confidence::Low,
                    Source::JsRegex,
                );
            }
        }

        // WebAssembly references (reported as-is).
        for (regex, label) in &self.wasm_patterns {
            for m in regex.find_iter(body) {
                push_unique(
                    &mut findings,
                    &mut seen,
                    session,
                    url,
                    format!("{label}: {}", snippet(body, m.start())),
                    Confidence::Low,
                    Source::JsRegex,
                );
            }
        }

        // postMessage receivers: a missing origin check in the handler window
        // is the interesting case, so it is bumped to Medium.
        for regex in &self.message {
            for m in regex.find_iter(body) {
                let mut end = (m.start() + ORIGIN_WINDOW).min(body.len());
                // Snap to a char boundary so slicing never panics.
                while end < body.len() && !body.is_char_boundary(end) {
                    end += 1;
                }
                let has_origin = body[m.start()..end].to_ascii_lowercase().contains("origin");
                let (label, confidence) = if has_origin {
                    ("postMessage receiver", Confidence::Low)
                } else {
                    (
                        "postMessage receiver (no origin check nearby)",
                        Confidence::Medium,
                    )
                };
                push_unique(
                    &mut findings,
                    &mut seen,
                    session,
                    url,
                    format!("{label}: {}", snippet(body, m.start())),
                    confidence,
                    Source::JsRegex,
                );
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
        DomSinkExtractor::new().extract(&input)
    }

    fn find_value<'a>(found: &'a [Finding], needle: &str) -> Option<&'a Finding> {
        found.iter().find(|f| f.value.contains(needle))
    }

    #[test]
    fn patterns_compile() {
        let _ = DomSinkExtractor::new();
    }

    #[test]
    fn traces_direct_source_to_sink_as_high() {
        let found = run("el.innerHTML = location.hash;");
        let f = find_value(&found, "DOM XSS: location.hash -> el.innerHTML")
            .expect("traced flow finding");
        assert_eq!(f.confidence, Confidence::High);
        assert_eq!(f.kind, FindingKind::Config);
        assert_eq!(f.provenance.source, Source::JsAst);
        // The regex lead for this sink is suppressed by the traced span.
        assert!(!found
            .iter()
            .any(|f| f.value.contains("dom sink (unverified source)")));
    }

    #[test]
    fn traces_variable_assignment_as_medium() {
        let js = "const dirty = location.search; el.innerHTML = dirty;";
        let found = run(js);
        let f = find_value(&found, "DOM XSS: location.search -> el.innerHTML")
            .expect("traced flow via variable");
        assert_eq!(f.confidence, Confidence::Medium);
        assert_eq!(f.provenance.source, Source::JsAst);
    }

    #[test]
    fn traces_concatenation_as_medium() {
        let found = run(r#"document.write("<h1>" + document.cookie + "</h1>");"#);
        let f = find_value(&found, "DOM XSS: document.cookie -> document.write")
            .expect("traced flow via concat");
        assert_eq!(f.confidence, Confidence::Medium);
    }

    #[test]
    fn traces_decoder_and_method_chain() {
        let found = run("el.innerHTML = decodeURIComponent(location.hash.slice(1));");
        let f = find_value(&found, "DOM XSS: location.hash -> el.innerHTML")
            .expect("decoder/method chain preserves taint");
        assert_eq!(f.confidence, Confidence::High);
    }

    #[test]
    fn traces_eval_and_new_function_and_insert_adjacent() {
        let js = r"
            eval(location.hash);
            const f = new Function(location.search);
            node.insertAdjacentHTML('beforeend', document.referrer);
        ";
        let found = run(js);
        assert!(find_value(&found, "DOM XSS: location.hash -> eval").is_some());
        assert!(find_value(&found, "DOM XSS: location.search -> new Function").is_some());
        assert!(
            find_value(&found, "-> node.insertAdjacentHTML").is_some(),
            "insertAdjacentHTML flow, got {:?}",
            found.iter().map(|f| &f.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn traces_location_navigation_sink() {
        let found = run("window.location.href = location.hash;");
        let f = find_value(&found, "DOM XSS: location.hash -> location.href")
            .expect("navigation sink flow");
        assert_eq!(f.confidence, Confidence::High);
    }

    #[test]
    fn traces_dangerously_set_inner_html() {
        let js =
            "const x = location.hash; const r = <div dangerouslySetInnerHTML={{__html: x}} />;";
        let found = run(js);
        let f = find_value(&found, "DOM XSS: location.hash -> dangerouslySetInnerHTML")
            .expect("React sink flow");
        assert_eq!(f.confidence, Confidence::Medium);
        assert_eq!(f.provenance.source, Source::JsAst);
    }

    #[test]
    fn traces_postmessage_handler_param() {
        let js = "window.addEventListener('message', function (e) { el.innerHTML = e.data; });";
        let found = run(js);
        let f = find_value(&found, "DOM XSS: event.data -> el.innerHTML")
            .expect("postMessage data flows to sink");
        assert_eq!(f.confidence, Confidence::Medium);
        // The receiver itself is still flagged (no origin check).
        assert!(found
            .iter()
            .any(|f| f.value.starts_with("postMessage receiver (no origin check")));
    }

    #[test]
    fn constant_sink_is_only_a_low_lead_never_traced() {
        let found = run(r#"el.innerHTML = "<b>constant</b>";"#);
        // No traced path.
        assert!(!found.iter().any(|f| f.value.starts_with("DOM XSS:")));
        assert!(found.iter().all(|f| f.confidence != Confidence::High));
        // A Low unverified lead keeps recall.
        let lead = find_value(&found, "dom sink (unverified source)").expect("low lead");
        assert_eq!(lead.confidence, Confidence::Low);
        assert_eq!(lead.provenance.source, Source::JsRegex);
    }

    #[test]
    fn untraced_sink_with_unknown_variable_is_low_lead() {
        // `userInput` has no tainted origin: a lead, not a traced path.
        let found = run("el.innerHTML = userInput;");
        assert!(!found.iter().any(|f| f.value.starts_with("DOM XSS:")));
        assert!(find_value(&found, "dom sink (unverified source)").is_some());
    }

    #[test]
    fn detects_wasm() {
        let js = r#"fetch("/app.wasm"); WebAssembly.instantiateStreaming(resp);"#;
        let found = run(js);
        assert!(find_value(&found, "WebAssembly module reference").is_some());
        assert!(find_value(&found, "WebAssembly instantiation").is_some());
    }

    #[test]
    fn postmessage_without_origin_is_medium() {
        let js = r"window.addEventListener('message', function (e) { handle(e.data); });";
        let found = run(js);
        let f = found
            .iter()
            .find(|f| f.value.starts_with("postMessage receiver"))
            .expect("postMessage finding");
        assert_eq!(f.confidence, Confidence::Medium);
        assert!(f.value.contains("no origin check"));
    }

    #[test]
    fn postmessage_with_origin_is_low() {
        let js = r"window.addEventListener('message', function (e) { if (e.origin !== OK) return; handle(e.data); });";
        let found = run(js);
        let f = found
            .iter()
            .find(|f| f.value.starts_with("postMessage receiver"))
            .expect("postMessage finding");
        assert_eq!(f.confidence, Confidence::Low);
    }

    #[test]
    fn negative_and_dedup() {
        // No sinks here.
        assert_eq!(run("const total = a + b; renderSafely(total);"), Vec::new());
        // Two identical traced sinks collapse to one finding.
        let js = "a.innerHTML = location.hash;\na.innerHTML = location.hash;";
        assert_eq!(run(js).len(), 1);
    }

    #[test]
    fn unparseable_returns_empty_not_error() {
        assert_eq!(run("function (() {{{ <<< "), Vec::new());
    }
}
