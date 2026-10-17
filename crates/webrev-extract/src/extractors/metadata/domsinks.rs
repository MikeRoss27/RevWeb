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
//! Ordinary extraction is intra-procedural and single-file. The separate
//! [`DomSinkExtractor::extract_modules`] batch pass links explicit ES-module
//! value/function imports across already collected files, with bounded work and static
//! candidates only. Export summaries require straight-line initialization;
//! module control flow and namespace imports are not modeled. Exported function
//! summaries require short, synchronous, straight-line declaration bodies.
//! There is **no**
//! cross-function propagation (a tainted value passed as an argument is not
//! tracked into the callee) and **no** aliasing analysis beyond simple
//! `x = <tainted>` assignments (no object-field, array-element, or destructuring
//! tracking). A tainted value's property access / method call is conservatively
//! assumed to stay tainted (`location.hash.slice(1)` is still tainted). Scope
//! lookup is lexical but generous: an inner closure can see an outer scope's
//! tainted variables. `DOMPurify.sanitize` is recognized for HTML sinks;
//! custom/framework sanitizers remain unmodelled, so a flow is a candidate.

mod modules;

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

/// Text hints for the conservative taint-AST gate. Matching is intentionally
/// broader than the AST model: comments, strings, or unrelated identifiers may
/// trigger a parse, but a possible source or sink must never be filtered out.
const TAINT_SOURCE_HINTS: &[&str] = &[
    "location",
    // Broad identifiers also cover whitespace around member-access dots.
    "document", "window", "self",
    // Covers the modeled `message` event parameter source even without a
    // global-object prefix (for example, `addEventListener(...)`).
    "message", ".data",
];

const TAINT_SINK_HINTS: &[&str] = &[
    "innerhtml",
    "outerhtml",
    "write",
    "eval",
    "new function",
    "insertadjacenthtml",
    "setattribute",
    "dangerouslysetinnerhtml",
    "__html",
];

const NAVIGATION_SINK_HINT: &str =
    r"(?i)\b(?:(?:window|self)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=";

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

/// String methods whose results cannot carry attacker-controlled markup or
/// code: they return only a number or boolean. Keeping these out of string
/// sinks prevents index/predicate values from being mistaken for tainted text.
const NON_STRING_RESULT_CALLS: &[&str] = &[
    "charCodeAt",
    "codePointAt",
    "indexOf",
    "lastIndexOf",
    "localeCompare",
    "search",
    "includes",
    "startsWith",
    "endsWith",
];

/// HTML event-handler attributes execute their string value as JavaScript.
fn is_event_handler_attribute(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "onabort"
            | "onanimationend"
            | "onanimationiteration"
            | "onanimationstart"
            | "onauxclick"
            | "onbeforeinput"
            | "onbeforeunload"
            | "onblur"
            | "onchange"
            | "onclick"
            | "oncontextmenu"
            | "oncopy"
            | "oncut"
            | "ondblclick"
            | "ondrag"
            | "ondragend"
            | "ondragenter"
            | "ondragleave"
            | "ondragover"
            | "ondragstart"
            | "ondrop"
            | "onerror"
            | "onfocus"
            | "oninput"
            | "oninvalid"
            | "onkeydown"
            | "onkeypress"
            | "onkeyup"
            | "onload"
            | "onmousedown"
            | "onmouseenter"
            | "onmouseleave"
            | "onmousemove"
            | "onmouseout"
            | "onmouseover"
            | "onmouseup"
            | "onpaste"
            | "onreset"
            | "onresize"
            | "onscroll"
            | "onselect"
            | "onsubmit"
            | "ontoggle"
            | "ontransitionend"
    )
}

/// How far past a `message` handler to look for an `origin` check.
const ORIGIN_WINDOW: usize = 240;

/// DOM-sink taint / postMessage / wasm extractor.
pub struct DomSinkExtractor {
    sink_patterns: Vec<(Regex, &'static str)>,
    wasm_patterns: Vec<(Regex, &'static str)>,
    message: Vec<Regex>,
    navigation_sink_hint: Regex,
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
        let navigation_sink_hint =
            Regex::new(NAVIGATION_SINK_HINT).expect("navigation sink hint is valid");
        Self {
            sink_patterns,
            wasm_patterns,
            message,
            navigation_sink_hint,
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

/// ASCII case-insensitive substring search without allocating a lowercase
/// copy of the full (often minified) bundle.
fn contains_ascii_case_insensitive(body: &str, needle: &str) -> bool {
    body.as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Skip only the expensive taint AST walk when the text cannot contain both a
/// modeled source and modeled sink. This gate is recall-preserving by design:
/// false positives keep the AST parse; only absence of every broad source or
/// sink hint skips it. The regex fallback and its independent analyses always
/// run regardless of this decision.
fn should_run_taint_ast(
    body: &str,
    message_patterns: &[Regex],
    navigation_sink_hint: &Regex,
) -> bool {
    let has_source = TAINT_SOURCE_HINTS
        .iter()
        .any(|hint| contains_ascii_case_insensitive(body, hint))
        || message_patterns
            .iter()
            .any(|pattern| pattern.is_match(body));
    has_source
        && (TAINT_SINK_HINTS
            .iter()
            .any(|hint| contains_ascii_case_insensitive(body, hint))
            || navigation_sink_hint.is_match(body))
}

fn sanitizer_wraps_sink(body: &str, start: usize) -> bool {
    let statement_start = body[..start].rfind([';', '\n']).map_or(0, |i| i + 1);
    let statement_end = body[start..]
        .find([';', '\n'])
        .map_or(body.len(), |i| start + i);
    body[statement_start..statement_end].contains("DOMPurify.sanitize(")
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

/// Drop a `window.`/`self.` global prefix and fold `document.location` into
/// `location`, which the DOM defines as the same object.
fn global_tail(path: &str) -> &str {
    let tail = path
        .strip_prefix("window.")
        .or_else(|| path.strip_prefix("self."))
        .unwrap_or(path);
    match tail.strip_prefix("document.") {
        Some(rest) if rest == "location" || rest.starts_with("location.") => rest,
        _ => tail,
    }
}

/// Map a member/identifier path to a canonical taint-source label, or `None`.
fn known_source(path: &str) -> Option<String> {
    let tail = global_tail(path);
    let had_prefix = path.starts_with("window.") || path.starts_with("self.");
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
    match global_tail(path) {
        "location" => Some("location"),
        "location.href" => Some("location.href"),
        _ => None,
    }
}

/// Truthiness of a literal `if` condition, so dead arms never contribute flows.
fn constant_condition(expr: &Expr) -> Option<bool> {
    use swc_core::ecma::ast::{Lit, UnaryOp};
    match expr {
        Expr::Paren(inner) => constant_condition(&inner.expr),
        Expr::Lit(Lit::Bool(value)) => Some(value.value),
        Expr::Lit(Lit::Null(_)) => Some(false),
        Expr::Lit(Lit::Num(value)) => Some(value.value != 0.0 && !value.value.is_nan()),
        Expr::Lit(Lit::Str(value)) => Some(!value.value.is_empty()),
        Expr::Unary(unary) if unary.op == UnaryOp::Bang => {
            constant_condition(&unary.arg).map(|truthy| !truthy)
        }
        _ => None,
    }
}

/// The live arms of an `if`: `(consequent, alternate)`.
fn live_arms(statement: &swc_core::ecma::ast::IfStmt) -> [Option<&swc_core::ecma::ast::Stmt>; 2] {
    let condition = constant_condition(&statement.test);
    [
        (condition != Some(false)).then_some(&*statement.cons),
        statement.alt.as_deref().filter(|_| condition != Some(true)),
    ]
}

fn pat_ident_name(pat: &Pat) -> Option<String> {
    if let Pat::Ident(bi) = pat {
        Some(bi.id.sym.as_ref().to_owned())
    } else {
        None
    }
}

/// Every binding in a parameter/pattern shadows an imported or outer name,
/// even when this lightweight analysis cannot model destructuring values.
fn pat_bound_names(pat: &Pat) -> Vec<String> {
    #[derive(Default)]
    struct Bindings(Vec<String>);
    impl Visit for Bindings {
        fn visit_binding_ident(&mut self, binding: &swc_core::ecma::ast::BindingIdent) {
            self.0.push(binding.id.sym.to_string());
        }
    }
    let mut bindings = Bindings::default();
    pat.visit_with(&mut bindings);
    bindings.0
}

/// Conservatively invalidate function bindings touched by an assignment target,
/// including destructuring. Member-object names may also be invalidated.
fn assigned_identifiers(target: &AssignTarget) -> Vec<String> {
    #[derive(Default)]
    struct Names(Vec<String>);
    impl Visit for Names {
        fn visit_ident(&mut self, id: &swc_core::ecma::ast::Ident) {
            self.0.push(id.sym.to_string());
        }
    }
    let mut names = Names::default();
    target.visit_with(&mut names);
    names.0
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
#[derive(Clone, Default, PartialEq, Eq)]
struct ImportedFunction {
    returns: Option<String>,
    /// Parameter index, transformations and sink label.
    sinks: Vec<(usize, String, String)>,
    locations: BTreeSet<String>,
}

struct TaintVisitor {
    imported_functions: BTreeMap<String, ImportedFunction>,
    module_calls_only: bool,
    linked_trace_locations: BTreeMap<String, BTreeSet<String>>,
    scopes: Vec<BTreeMap<String, Option<String>>>,
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
            imported_functions: BTreeMap::new(),
            module_calls_only: false,
            linked_trace_locations: BTreeMap::new(),
            handler_spans: BTreeSet::new(),
            traces: Vec::new(),
            traced_spans: Vec::new(),
        }
    }

    fn module_binding_shadows(&self, name: &str) -> bool {
        self.module_calls_only && self.scopes.iter().any(|scope| scope.contains_key(name))
    }

    fn lookup(&self, name: &str) -> Option<String> {
        self.scopes
            .iter()
            .rev()
            .find_map(|s| s.get(name))
            .cloned()
            .flatten()
    }

    fn insert_var(&mut self, name: String, origin: String) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(name, Some(origin));
        }
    }

    fn imported_function(&self, name: &str) -> Option<&ImportedFunction> {
        if self
            .scopes
            .iter()
            .skip(1)
            .any(|scope| scope.contains_key(name))
        {
            return None;
        }
        self.imported_functions.get(name)
    }

    fn clear_var(&mut self, name: &str) {
        self.imported_functions.remove(name);
        for scope in self.scopes.iter_mut().rev() {
            if let Some(value) = scope.get_mut(name) {
                *value = None;
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
                } else if name == "location" && !self.module_binding_shadows(name) {
                    Some(("location".to_owned(), true))
                } else {
                    None
                }
            }
            Expr::Member(m) => {
                if member_prop_name(m).as_deref() == Some("length") {
                    return None;
                }
                if let Some(path) = member_expr_path(m) {
                    if let Some(label) = known_source(&path).filter(|_| {
                        !self.module_binding_shadows(path.split('.').next().unwrap_or_default())
                    }) {
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
            Expr::Member(m) if member_expr_path(m).as_deref() == Some("DOMPurify.sanitize") => None,
            // `tainted.method(...)` (string methods preserve taint).
            Expr::Member(m) => {
                let transformation = member_prop_name(m).unwrap_or_else(|| "method".into());
                if NON_STRING_RESULT_CALLS.contains(&transformation.as_str()) {
                    return None;
                }
                self.classify(&m.obj)
                    .map(|(origin, _)| (format!("{origin} -> {transformation}"), false))
            }
            Expr::Ident(id) if self.imported_function(id.sym.as_ref()).is_some() => self
                .imported_function(id.sym.as_ref())?
                .returns
                .clone()
                .map(|origin| (origin, false)),
            // `decodeURIComponent(tainted)` and friends.
            Expr::Ident(id) if TAINT_PRESERVING_CALLS.contains(&id.sym.as_ref()) => self
                .first_tainted_arg(&call.args)
                .map(|(origin, _)| (format!("{origin} -> {}", id.sym), false)),
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
                } else if is_event_handler_attribute(&prop) {
                    if let Some(taint) = self.classify(&assign.right) {
                        self.trace(taint, &format!("event handler {prop}"), assign.span());
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
        let AssignTarget::Simple(SimpleAssignTarget::Ident(bi)) = &assign.left else {
            return;
        };
        let name = bi.id.sym.as_ref();
        self.imported_functions.remove(name);
        if name == "location" {
            return;
        }
        let name = name.to_owned();
        if assign.op != AssignOp::Assign {
            self.clear_var(&name);
            return;
        }
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
        let is_add_event_listener = match &**callee {
            Expr::Member(m) => member_prop_name(m).as_deref() == Some("addEventListener"),
            Expr::Ident(id) => id.sym.as_ref() == "addEventListener",
            _ => false,
        };
        if !is_add_event_listener {
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
        if let Callee::Expr(callee) = &call.callee {
            if let Expr::Ident(id) = &**callee {
                if let Some(function) = self
                    .imported_function(id.sym.as_ref())
                    .cloned()
                    .filter(|_| call.args.iter().all(|arg| arg.spread.is_none()))
                {
                    for (index, suffix, sink) in function.sinks {
                        let Some(arg) = call.args.get(index).filter(|arg| arg.spread.is_none())
                        else {
                            continue;
                        };
                        if let Some((origin, _)) = self.classify(&arg.expr) {
                            let origin = format!("{origin}{suffix}");
                            let flow = format!("DOM XSS: {origin} -> {sink}");
                            self.linked_trace_locations
                                .entry(flow)
                                .or_default()
                                .extend(function.locations.iter().cloned());
                            self.trace((origin, false), &sink, call.span());
                        }
                    }
                    return;
                }
            }
        }
        let Callee::Expr(callee) = &call.callee else {
            return;
        };
        match &**callee {
            Expr::Ident(id)
                if id.sym.as_ref() == "eval" && !self.module_binding_shadows("eval") =>
            {
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
        if lower == "setattribute" {
            let args = call.args.as_slice();
            if let (
                Some(ExprOrSpread {
                    expr: first,
                    spread: None,
                }),
                Some(ExprOrSpread {
                    expr: second,
                    spread: None,
                }),
            ) = (args.first(), args.get(1))
            {
                if let Expr::Lit(Lit::Str(attribute)) = &**first {
                    let attribute = attribute.value.to_string_lossy();
                    if is_event_handler_attribute(&attribute) {
                        if let Some(taint) = self.classify(second) {
                            self.trace(taint, &format!("setAttribute({attribute})"), call.span());
                        }
                    }
                }
            }
        } else if (lower == "write" || lower == "writeln") && object_is_document(m) {
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
    fn visit_if_stmt(&mut self, statement: &swc_core::ecma::ast::IfStmt) {
        if self.module_calls_only {
            if let Expr::Lit(Lit::Bool(test)) = &*statement.test {
                if test.value {
                    statement.cons.visit_with(self);
                } else if let Some(alternate) = &statement.alt {
                    alternate.visit_with(self);
                }
                return;
            }
        }
        statement.visit_children_with(self);
    }

    fn visit_cond_expr(&mut self, expression: &swc_core::ecma::ast::CondExpr) {
        if self.module_calls_only {
            if let Expr::Lit(Lit::Bool(test)) = &*expression.test {
                if test.value {
                    expression.cons.visit_with(self);
                } else {
                    expression.alt.visit_with(self);
                }
                return;
            }
        }
        expression.visit_children_with(self);
    }

    fn visit_update_expr(&mut self, update: &swc_core::ecma::ast::UpdateExpr) {
        if let Expr::Ident(id) = &*update.arg {
            self.imported_functions.remove(id.sym.as_ref());
            self.clear_var(id.sym.as_ref());
        }
        update.visit_children_with(self);
    }

    fn visit_block_stmt(&mut self, block: &swc_core::ecma::ast::BlockStmt) {
        if !self.module_calls_only {
            block.visit_children_with(self);
            return;
        }
        let mut bindings = BTreeMap::new();
        for statement in &block.stmts {
            match statement {
                swc_core::ecma::ast::Stmt::Decl(swc_core::ecma::ast::Decl::Var(var)) => {
                    for decl in &var.decls {
                        for name in pat_bound_names(&decl.name) {
                            bindings.insert(name, None);
                        }
                    }
                }
                swc_core::ecma::ast::Stmt::Decl(swc_core::ecma::ast::Decl::Fn(function)) => {
                    bindings.insert(function.ident.sym.to_string(), None);
                }
                _ => {}
            }
        }
        self.scopes.push(bindings);
        block.visit_children_with(self);
        self.scopes.pop();
    }

    fn visit_assign_expr(&mut self, assign: &AssignExpr) {
        for name in assigned_identifiers(&assign.left) {
            self.imported_functions.remove(&name);
        }
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
            if id.sym.as_ref() == "Function" && !self.module_binding_shadows("Function") {
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
        for name in pat_bound_names(&decl.name) {
            self.imported_functions.remove(&name);
        }
        if let Pat::Ident(bi) = &decl.name {
            let origin = decl
                .init
                .as_ref()
                .and_then(|init| self.classify(init))
                .map(|(origin, _)| origin);
            self.scopes
                .last_mut()
                .expect("scope exists")
                .insert(bi.id.sym.to_string(), origin);
        } else {
            for name in pat_bound_names(&decl.name) {
                self.scopes
                    .last_mut()
                    .expect("scope exists")
                    .insert(name, None);
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
        if self.module_calls_only {
            return;
        }
        let is_handler = self.handler_spans.contains(&span_tuple(f.span()));
        self.scopes.push(BTreeMap::new());
        for param in &f.params {
            for name in pat_bound_names(&param.pat) {
                self.scopes
                    .last_mut()
                    .expect("scope exists")
                    .insert(name, None);
            }
        }
        let first_param = f.params.first().and_then(|p| pat_ident_name(&p.pat));
        self.seed_handler_param(first_param, is_handler);
        f.visit_children_with(self);
        self.scopes.pop();
    }

    fn visit_catch_clause(&mut self, clause: &swc_core::ecma::ast::CatchClause) {
        self.scopes.push(BTreeMap::new());
        if let Some(param) = &clause.param {
            for name in pat_bound_names(param) {
                self.scopes
                    .last_mut()
                    .expect("scope exists")
                    .insert(name, None);
            }
        }
        clause.body.visit_with(self);
        self.scopes.pop();
    }

    fn visit_arrow_expr(&mut self, a: &ArrowExpr) {
        if self.module_calls_only {
            return;
        }
        let is_handler = self.handler_spans.contains(&span_tuple(a.span()));
        self.scopes.push(BTreeMap::new());
        for param in &a.params {
            for name in pat_bound_names(param) {
                self.scopes
                    .last_mut()
                    .expect("scope exists")
                    .insert(name, None);
            }
        }
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
        let (traces, traced_spans) =
            if should_run_taint_ast(body, &self.message, &self.navigation_sink_hint) {
                run_taint(body)
            } else {
                (Vec::new(), Vec::new())
            };
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
                if sanitizer_wraps_sink(body, start) {
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
    include!("domsinks_tests.rs");
}
