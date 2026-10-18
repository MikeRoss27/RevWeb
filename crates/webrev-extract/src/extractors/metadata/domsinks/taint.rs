// crates/webrev-extract/src/extractors/metadata/domsinks/taint.rs
//! Intra-procedural taint tracker state and flow rules; the AST traversal
//! lives in [`visit`].

mod visit;

use super::ast::{
    fn_or_arrow_span, member_expr_path, member_prop_name, object_is_document, span_tuple,
};
use super::sinks::{is_event_handler_attribute, nav_sink, NON_STRING_RESULT_CALLS};
use super::sources::{known_source, TAINT_PRESERVING_CALLS};
use std::collections::{BTreeMap, BTreeSet};
use swc_core::common::Spanned;
use swc_core::ecma::ast::{
    AssignExpr, AssignOp, AssignTarget, BinaryOp, CallExpr, Callee, Expr, ExprOrSpread, Lit,
    MemberExpr, SimpleAssignTarget,
};
use webrev_core::Confidence;

/// A value found to carry taint: `(origin label, direct)`. `direct` is true
/// only when the value *is* a source expression (not laundered through a
/// variable or a concatenation), which drives `High` vs `Medium` confidence.
pub(super) type Taint = (String, bool);

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

    pub(super) fn imported_function(&self, name: &str) -> Option<&ImportedFunction> {
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

    pub(super) fn classify_call(&self, call: &CallExpr) -> Option<Taint> {
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

    pub(super) fn first_tainted_arg(&self, args: &[ExprOrSpread]) -> Option<Taint> {
        args.iter()
            .filter(|a| a.spread.is_none())
            .find_map(|a| self.classify(&a.expr))
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
