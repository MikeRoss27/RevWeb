// crates/webrev-extract/src/extractors/metadata/domsinks/taint.rs
//! Intra-procedural taint tracker state and flow rules; the AST traversal
//! lives in [`visit`].

mod visit;

use super::ast::{
    fn_or_arrow_span, member_expr_path, member_prop_name, object_is_document, span_tuple,
};
use super::sinks::{is_event_handler_attribute, nav_sink, NON_STRING_RESULT_CALLS};
use super::sources::{known_source, TAINT_PRESERVING_CALLS, TAINT_PRESERVING_CONSTRUCTORS};
use std::collections::{BTreeMap, BTreeSet};
use swc_core::common::Spanned;
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, AssignTarget, BinaryOp, CallExpr, Callee, Expr, ExprOrSpread, Lit,
    MemberExpr, NewExpr, SimpleAssignTarget,
};
use webrev_core::Confidence;

/// A value found to carry taint: `(origin label, direct)`. `direct` is true
/// only when the value *is* a source expression (not laundered through a
/// variable or a concatenation), which drives `High` vs `Medium` confidence.
pub(super) type Taint = (String, bool);

/// The two HTML metacharacters that actually enable tag/attribute injection.
/// A hand-rolled entity-encoding `.replace()` chain is only treated as
/// taint-breaking once it covers *both* of these — escaping `&` alone (or
/// quotes alone) still lets `<script>` through, so it must not clear taint.
const REQUIRED_ESCAPED: [char; 2] = ['<', '>'];

/// If `pattern` is a one-character literal or a single-flag-`g` one-character
/// regex matching an HTML metacharacter, and `replacement` is the matching
/// HTML entity, return that character. Used to recognise one link of a
/// `s.replace(/</g, '&lt;').replace(/>/g, '&gt;')`-style sanitizing chain
/// without mistaking an arbitrary, unrelated `.replace()` call for one.
fn replace_escapes_char(args: &[ExprOrSpread]) -> Option<char> {
    let [pattern, replacement] = args else {
        return None;
    };
    if pattern.spread.is_some() || replacement.spread.is_some() {
        return None;
    }
    let target = match &*pattern.expr {
        Expr::Lit(Lit::Str(s)) => single_char(&s.value.to_string_lossy()),
        Expr::Lit(Lit::Regex(r)) if r.flags.as_ref().contains('g') => {
            single_char_regex_source(r.exp.as_ref())
        }
        _ => None,
    }?;
    if !"&<>\"'".contains(target) {
        return None;
    }
    let Expr::Lit(Lit::Str(replacement)) = &*replacement.expr else {
        return None;
    };
    let entities: &[&str] = match target {
        '&' => &["&amp;"],
        '<' => &["&lt;"],
        '>' => &["&gt;"],
        '"' => &["&quot;"],
        '\'' => &["&#39;", "&apos;"],
        _ => return None,
    };
    let replacement = replacement.value.to_string_lossy();
    entities
        .iter()
        .any(|entity| replacement.eq_ignore_ascii_case(entity))
        .then_some(target)
}

/// A string that is exactly one character.
fn single_char(value: &str) -> Option<char> {
    let mut chars = value.chars();
    let only = chars.next()?;
    chars.next().is_none().then_some(only)
}

/// A regex source that matches exactly one (optionally backslash-escaped)
/// character, e.g. `&`, `<` or `\<`.
fn single_char_regex_source(source: &str) -> Option<char> {
    match source.chars().collect::<Vec<_>>().as_slice() {
        [c] | ['\\', c] => Some(*c),
        _ => None,
    }
}

/// Intra-procedural taint tracker. Scopes are a stack of
/// `variable name -> taint origin`; `message` handler parameters are seeded as
/// tainted on scope entry.
#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct ImportedFunction {
    pub(super) returns: Option<String>,
    /// Parameter index, transformations and sink label.
    pub(super) sinks: Vec<(usize, String, String)>,
    pub(super) locations: BTreeSet<String>,
}

pub(super) struct TaintVisitor {
    pub(super) imported_functions: BTreeMap<String, ImportedFunction>,
    pub(super) module_calls_only: bool,
    pub(super) linked_trace_locations: BTreeMap<String, BTreeSet<String>>,
    pub(super) scopes: Vec<BTreeMap<String, Option<String>>>,
    /// Byte-range spans of function/arrow literals that are `message` handlers,
    /// so their first parameter can be seeded as tainted.
    pub(super) handler_spans: BTreeSet<(usize, usize)>,
    /// Traced `source -> sink` flows as `(value, confidence)`.
    pub(super) traces: Vec<(String, Confidence)>,
    /// Byte-range spans of statements/expressions that carried a traced flow,
    /// used to suppress the redundant regex "unverified source" lead.
    pub(super) traced_spans: Vec<(usize, usize)>,
}

impl TaintVisitor {
    pub(super) fn new() -> Self {
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

    pub(super) fn module_binding_shadows(&self, name: &str) -> bool {
        self.module_calls_only && self.scopes.iter().any(|scope| scope.contains_key(name))
    }

    pub(super) fn lookup(&self, name: &str) -> Option<String> {
        self.scopes
            .iter()
            .rev()
            .find_map(|s| s.get(name))
            .cloned()
            .flatten()
    }

    pub(super) fn insert_var(&mut self, name: String, origin: String) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(name, Some(origin));
        }
    }

    /// `name` is a plain binding or a seeded `namespace.export` path; an inner
    /// binding of the plain name or of the namespace hides it.
    pub(super) fn imported_function(&self, name: &str) -> Option<&ImportedFunction> {
        let root = name.split('.').next().unwrap_or(name);
        if self
            .scopes
            .iter()
            .skip(1)
            .any(|scope| scope.contains_key(root))
        {
            return None;
        }
        self.imported_functions.get(name)
    }

    /// Taint of `namespace.export` for a namespace import. The dotted key only
    /// exists at module scope, so any inner binding of the namespace hides it.
    fn namespace_member(&self, path: &str) -> Option<String> {
        let (namespace, _) = path.split_once('.')?;
        if self
            .scopes
            .iter()
            .skip(1)
            .any(|scope| scope.contains_key(namespace))
        {
            return None;
        }
        self.scopes.first()?.get(path).cloned().flatten()
    }

    pub(super) fn clear_var(&mut self, name: &str) {
        self.imported_functions.remove(name);
        for scope in self.scopes.iter_mut().rev() {
            if let Some(value) = scope.get_mut(name) {
                *value = None;
                return;
            }
        }
    }

    /// Classify an expression's taint, following the three flow rules.
    pub(super) fn classify(&self, expr: &Expr) -> Option<Taint> {
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
                    if let Some(origin) = self.namespace_member(&path) {
                        return Some((origin, false));
                    }
                }
                // Property of a tainted value stays tainted (conservative).
                self.classify(&m.obj)
            }
            Expr::Call(call) => self.classify_call(call),
            Expr::New(new_expr) => self.classify_new(new_expr),
            // `+` concatenation and the `||`/`??`/`&&` fallback idioms
            // (`param || "default"`, `param ?? "default"`) all may evaluate
            // to either operand, so a tainted operand on either side taints
            // the whole expression.
            Expr::Bin(bin)
                if matches!(
                    bin.op,
                    BinaryOp::Add
                        | BinaryOp::LogicalOr
                        | BinaryOp::LogicalAnd
                        | BinaryOp::NullishCoalescing
                ) =>
            {
                self.classify(&bin.left)
                    .or_else(|| self.classify(&bin.right))
                    .map(|(origin, _)| (origin, false))
            }
            Expr::Tpl(tpl) => tpl
                .exprs
                .iter()
                .find_map(|e| self.classify(e))
                .map(|(origin, _)| (origin, false)),
            _ => None,
        }
    }

    pub(super) fn classify_call(&self, call: &CallExpr) -> Option<Taint> {
        let Callee::Expr(callee) = &call.callee else {
            return None;
        };
        match &**callee {
            Expr::Member(m) if member_expr_path(m).as_deref() == Some("DOMPurify.sanitize") => None,
            // `tainted.replace(pattern, entity)`, possibly chained: break taint
            // only once the chain covers both `<` and `>` (see
            // `REQUIRED_ESCAPED`); an unrecognised or incomplete chain falls
            // back to the generic taint-preserving method-call rule below so
            // a lone unrelated `.replace()` call still propagates taint.
            Expr::Member(m)
                if matches!(
                    member_prop_name(m).as_deref(),
                    Some("replace" | "replaceAll")
                ) =>
            {
                let transformation = member_prop_name(m).unwrap_or_else(|| "method".into());
                match replace_escapes_char(&call.args) {
                    Some(ch) => {
                        let mut escaped = BTreeSet::from([ch]);
                        let base = self.replace_chain_base(&m.obj, &mut escaped)?;
                        if REQUIRED_ESCAPED.iter().all(|c| escaped.contains(c)) {
                            None
                        } else {
                            Some((format!("{} -> {transformation}", base.0), false))
                        }
                    }
                    None => self
                        .classify(&m.obj)
                        .map(|(origin, _)| (format!("{origin} -> {transformation}"), false)),
                }
            }
            // `namespace.exported(...)` for a namespace import.
            Expr::Member(m)
                if member_expr_path(m)
                    .is_some_and(|path| self.imported_function(&path).is_some()) =>
            {
                let function = self.imported_function(&member_expr_path(m)?)?;
                function.returns.clone().map(|origin| (origin, false))
            }
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

    /// `new URL(tainted)` / `new URLSearchParams(tainted)`: the constructed
    /// object carries the argument's taint, so a later `.search`, `.href` or
    /// `.searchParams.get(...)` on it is still caught by the member-access
    /// and method-call rules in [`Self::classify`] / [`Self::classify_call`].
    pub(super) fn classify_new(&self, new_expr: &NewExpr) -> Option<Taint> {
        let Expr::Ident(id) = &*new_expr.callee else {
            return None;
        };
        let name = id.sym.as_ref();
        if !TAINT_PRESERVING_CONSTRUCTORS.contains(&name) || self.module_binding_shadows(name) {
            return None;
        }
        let args = new_expr.args.as_deref()?;
        self.first_tainted_arg(args)
            .map(|(origin, _)| (format!("{origin} -> new {name}"), false))
    }

    pub(super) fn first_tainted_arg(&self, args: &[ExprOrSpread]) -> Option<Taint> {
        args.iter()
            .filter(|a| a.spread.is_none())
            .find_map(|a| self.classify(&a.expr))
    }

    /// Walk further down a `.replace()` chain, recording each additional
    /// escaped character into `escaped`, until a non-escaping link or the
    /// tainted base value is reached.
    fn replace_chain_base(&self, expr: &Expr, escaped: &mut BTreeSet<char>) -> Option<Taint> {
        if let Expr::Paren(p) = expr {
            return self.replace_chain_base(&p.expr, escaped);
        }
        if let Expr::Call(call) = expr {
            if let Callee::Expr(callee) = &call.callee {
                if let Expr::Member(m) = &**callee {
                    if matches!(
                        member_prop_name(m).as_deref(),
                        Some("replace" | "replaceAll")
                    ) {
                        if let Some(ch) = replace_escapes_char(&call.args) {
                            escaped.insert(ch);
                            return self.replace_chain_base(&m.obj, escaped);
                        }
                    }
                }
            }
        }
        self.classify(expr)
    }

    /// Record a traced `source -> sink` flow and the span it covers.
    pub(super) fn trace(
        &mut self,
        (origin, direct): Taint,
        sink: &str,
        span: swc_core::common::Span,
    ) {
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
    pub(super) fn seed_handler_param(&mut self, first_param: Option<String>, is_handler: bool) {
        if is_handler {
            if let Some(name) = first_param {
                self.insert_var(name, "event.data".to_owned());
            }
        }
    }

    /// Handle the sink/registration logic of an assignment (`=` only).
    pub(super) fn assign_sink(&mut self, assign: &AssignExpr) {
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
    pub(super) fn assign_var(&mut self, assign: &AssignExpr) {
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
    pub(super) fn register_onmessage(&mut self, assign: &AssignExpr) {
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
    pub(super) fn register_addeventlistener(&mut self, call: &CallExpr) {
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
    pub(super) fn call_sink(&mut self, call: &CallExpr) {
        if let Callee::Expr(callee) = &call.callee {
            let name = match &**callee {
                Expr::Ident(id) => Some(id.sym.to_string()),
                Expr::Member(m) => member_expr_path(m),
                _ => None,
            };
            if let Some(function) = name
                .and_then(|name| self.imported_function(&name).cloned())
                .filter(|_| call.args.iter().all(|arg| arg.spread.is_none()))
            {
                for (index, suffix, sink) in function.sinks {
                    let Some(arg) = call.args.get(index).filter(|arg| arg.spread.is_none()) else {
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

    pub(super) fn member_call_sink(&mut self, call: &CallExpr, m: &MemberExpr) {
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
