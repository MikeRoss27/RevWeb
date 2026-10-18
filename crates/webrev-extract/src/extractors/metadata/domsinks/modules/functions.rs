use super::{
    exported_locals, locations, BTreeMap, BTreeSet, Decl, ExportValue, Expr, ImportedFunction,
    ModuleDecl, ModuleItem, ParsedModule, Stmt, TaintVisitor, VisitWith,
};
use crate::extractors::metadata::domsinks::ast::{assigned_identifiers, live_arms, pat_ident_name};
use swc_core::ecma::ast::{AssignTarget, Function, FunctionBody, SimpleAssignTarget, VarDeclKind};
use swc_core::ecma::visit::Visit;

// Summaries intentionally cover only ordinary synchronous function declarations
// with a short, straight-line body. No call graph or body cloning is needed.
pub(super) fn function_exports(
    parsed: &ParsedModule,
    module_visitor: &TaintVisitor,
    imports: &BTreeMap<String, ExportValue>,
) -> BTreeMap<String, ExportValue> {
    let bindings = exported_locals(&parsed.module);
    // One level of same-module helpers; helpers do not see each other.
    let helpers = local_functions(parsed, module_visitor, imports);
    summaries(parsed, module_visitor, imports, bindings, &helpers)
}

/// Summaries of every module-level function declaration, keyed by its local
/// name, so calls to helpers in the same module can carry taint.
pub(super) fn local_functions(
    parsed: &ParsedModule,
    module_visitor: &TaintVisitor,
    imports: &BTreeMap<String, ExportValue>,
) -> BTreeMap<String, ImportedFunction> {
    let bindings = parsed
        .module
        .body
        .iter()
        .filter_map(|item| match item {
            ModuleItem::Stmt(Stmt::Decl(Decl::Fn(function)))
            | ModuleItem::ModuleDecl(ModuleDecl::ExportDecl(swc_core::ecma::ast::ExportDecl {
                decl: Decl::Fn(function),
                ..
            })) => {
                let name = function.ident.sym.to_string();
                Some((name.clone(), name))
            }
            _ => None,
        })
        .collect();
    summaries(parsed, module_visitor, imports, bindings, &BTreeMap::new())
        .into_iter()
        .filter_map(|(name, value)| Some((name, value.function?)))
        .collect()
}

fn summaries(
    parsed: &ParsedModule,
    module_visitor: &TaintVisitor,
    imports: &BTreeMap<String, ExportValue>,
    bindings: Vec<(String, String)>,
    helpers: &BTreeMap<String, ImportedFunction>,
) -> BTreeMap<String, ExportValue> {
    if ["document", "location", "window", "self", "eval", "Function"]
        .iter()
        .any(|name| module_visitor.scopes[0].contains_key(*name))
    {
        return BTreeMap::new();
    }
    let mut declarations = BTreeMap::new();
    let mut overwritten = BTreeSet::new();
    for item in &parsed.module.body {
        let decl = match item {
            ModuleItem::Stmt(Stmt::Decl(decl)) => Some(decl),
            ModuleItem::ModuleDecl(ModuleDecl::ExportDecl(export)) => Some(&export.decl),
            _ => None,
        };
        if let Some(Decl::Fn(function)) = decl {
            declarations.insert(function.ident.sym.to_string(), &*function.function);
        }
        if let ModuleItem::Stmt(Stmt::Expr(expression)) = item {
            let mut mutations = Mutations::default();
            expression.visit_with(&mut mutations);
            overwritten.extend(mutations.0);
        }
    }
    let mut result = BTreeMap::new();
    for (exported, local) in bindings.into_iter().take(64) {
        if overwritten.contains(&local) {
            continue;
        }
        let Some(function) = declarations.get(&local) else {
            continue;
        };
        let Some(mut summary) = function_summary(function, helpers, &local, 0) else {
            continue;
        };
        let mut evidence = BTreeSet::from([parsed.url.to_string()]);
        if let Some(origin) = &summary.returns {
            evidence.extend(locations(origin, parsed, imports));
        }
        summary.locations.clone_from(&evidence);
        result.insert(
            exported,
            ExportValue {
                origin: summary.returns.clone().unwrap_or_default(),
                locations: evidence,
                function: Some(summary),
            },
        );
    }
    result
}

/// Return and parameter-sink summary of one synchronous, bounded function.
/// `depth` 0 also summarizes helpers declared inside the body; those do not
/// nest further.
fn function_summary(
    function: &Function,
    helpers: &BTreeMap<String, ImportedFunction>,
    own_name: &str,
    depth: usize,
) -> Option<ImportedFunction> {
    if function.is_async || function.is_generator || function.params.len() > 16 {
        return None;
    }
    let body = function.body.as_ref()?;
    if body.stmts.len() > 64 {
        return None;
    }
    let mut helpers = helpers.clone();
    if depth == 0 {
        for statement in &body.stmts {
            if let Stmt::Decl(Decl::Fn(inner)) = statement {
                let name = inner.ident.sym.to_string();
                if name != own_name {
                    if let Some(summary) =
                        function_summary(&inner.function, &BTreeMap::new(), &name, 1)
                    {
                        helpers.insert(name, summary);
                    }
                }
            }
        }
    }
    let (visitor, returned) = analyze_body(function, body, &helpers, own_name)?;
    let mut summary = ImportedFunction {
        returns: returned.filter(|origin| !origin.contains('\0')),
        ..ImportedFunction::default()
    };
    for (trace, _) in visitor.traces {
        let Some((origin, sink)) = trace
            .strip_prefix("DOM XSS: ")
            .and_then(|flow| flow.rsplit_once(" -> "))
        else {
            continue;
        };
        for index in 0..function.params.len() {
            let marker = format!("\0module-parameter-{index}");
            if let Some(suffix) = origin.strip_prefix(&marker) {
                if suffix.is_empty() || suffix.starts_with(" -> ") {
                    summary
                        .sinks
                        .push((index, suffix.to_owned(), sink.to_owned()));
                }
            }
        }
    }
    (summary.returns.is_some() || !summary.sinks.is_empty()).then_some(summary)
}

fn analyze_body(
    function: &Function,
    body: &FunctionBody,
    helpers: &BTreeMap<String, ImportedFunction>,
    own_name: &str,
) -> Option<(TaintVisitor, Option<String>)> {
    let mut visitor = TaintVisitor::new();
    visitor.module_calls_only = true;
    for (name, helper) in helpers {
        if name != own_name {
            visitor.scopes[0].insert(name.clone(), None);
            visitor
                .imported_functions
                .insert(name.clone(), helper.clone());
        }
    }
    // Captured module variables can be mutated by other exports. Only local
    // bindings and direct global sources participate in function summaries.
    let mut mutations = Mutations::default();
    body.visit_with(&mut mutations);
    if ["document", "location", "window", "self", "eval", "Function"]
        .iter()
        .any(|name| mutations.0.contains(*name))
    {
        return None;
    }
    // Imported calls are deliberately not summarized recursively.
    visitor.scopes.push(BTreeMap::new());
    let mut valid = true;
    for (index, parameter) in function.params.iter().enumerate() {
        let Some(name) = pat_ident_name(&parameter.pat) else {
            valid = false;
            break;
        };
        if ["document", "location", "window", "self", "eval", "Function"].contains(&name.as_str()) {
            valid = false;
            break;
        }
        visitor.insert_var(name, format!("\0module-parameter-{index}"));
    }
    let mut returned = None;
    let last = body.stmts.len().saturating_sub(1);
    for (index, statement) in body.stmts.iter().enumerate() {
        if !valid {
            break;
        }
        // A top-level `return` must end the body; branches may return early.
        if matches!(statement, Stmt::Return(_)) && index != last {
            valid = false;
            break;
        }
        valid = apply_statement(&mut visitor, statement, &mut returned, false).is_some();
    }
    if !valid || visitor.traces.len() > 32 {
        return None;
    }
    Some((visitor, returned))
}

const RESERVED: [&str; 6] = ["document", "location", "window", "self", "eval", "Function"];

/// Apply one statement of a summarized function body. `nested` marks statements
/// inside an `if` arm, where only `var` declarations (function-scoped) are
/// understood. `None` makes the whole summary unavailable.
fn apply_statement(
    visitor: &mut TaintVisitor,
    statement: &Stmt,
    returned: &mut Option<String>,
    nested: bool,
) -> Option<()> {
    match statement {
        Stmt::Decl(Decl::Var(var)) => {
            if nested && var.kind != VarDeclKind::Var {
                return None;
            }
            for decl in &var.decls {
                let name = pat_ident_name(&decl.name)?;
                if RESERVED.contains(&name.as_str())
                    || decl
                        .init
                        .as_deref()
                        .is_some_and(|expr| matches!(expr, Expr::Fn(_) | Expr::Arrow(_)))
                {
                    return None;
                }
            }
            statement.visit_with(visitor);
        }
        Stmt::Expr(_) | Stmt::Empty(_) => statement.visit_with(visitor),
        // Helper functions (e.g. an async `trigger`) are scanned for sinks but
        // are not summarized; a name that collides with a reserved global is not.
        Stmt::Decl(Decl::Fn(function))
            if !nested && !RESERVED.contains(&function.ident.sym.as_ref()) =>
        {
            statement.visit_with(visitor);
        }
        Stmt::Return(ret) => {
            if returned.is_none() {
                *returned = ret
                    .arg
                    .as_deref()
                    .and_then(|expr| visitor.classify(expr))
                    .map(|(origin, _)| origin);
            }
        }
        Stmt::Block(block) if nested => {
            for inner in &block.stmts {
                apply_statement(visitor, inner, returned, true)?;
            }
        }
        Stmt::If(branches) => {
            merge_arms(visitor, live_arms(branches), returned)?;
        }
        // A loop body may run zero or more times; one pass with a may-taint merge
        // against the skipped path is enough for a flat taint map.
        Stmt::For(looped) => merge_arms(visitor, [Some(&*looped.body), None], returned)?,
        Stmt::While(looped) => merge_arms(visitor, [Some(&*looped.body), None], returned)?,
        _ => return None,
    }
    Some(())
}

/// May-taint merge: a binding tainted before the construct or in any arm stays
/// tainted, and the first tainted `return` wins.
fn merge_arms(
    visitor: &mut TaintVisitor,
    arms: [Option<&Stmt>; 2],
    returned: &mut Option<String>,
) -> Option<()> {
    let base = visitor.scopes.last()?.clone();
    let mut merged = base.clone();
    for arm in arms {
        *visitor.scopes.last_mut()? = base.clone();
        if let Some(arm) = arm {
            apply_statement(visitor, arm, returned, true)?;
        }
        for (name, origin) in visitor.scopes.last()? {
            let slot = merged.entry(name.clone()).or_insert(None);
            if slot.is_none() {
                slot.clone_from(origin);
            }
        }
    }
    *visitor.scopes.last_mut()? = merged;
    Some(())
}

#[derive(Default)]
struct Mutations(BTreeSet<String>);
impl Visit for Mutations {
    fn visit_assign_expr(&mut self, assign: &swc_core::ecma::ast::AssignExpr) {
        // `obj.prop = v` writes a property and does not rebind `obj`.
        if !matches!(
            &assign.left,
            AssignTarget::Simple(SimpleAssignTarget::Member(_))
        ) {
            self.0.extend(assigned_identifiers(&assign.left));
        }
        assign.visit_children_with(self);
    }
    fn visit_update_expr(&mut self, update: &swc_core::ecma::ast::UpdateExpr) {
        if let Expr::Ident(id) = &*update.arg {
            self.0.insert(id.sym.to_string());
        }
        update.visit_children_with(self);
    }
    fn visit_function(&mut self, _function: &Function) {}
    fn visit_arrow_expr(&mut self, _arrow: &swc_core::ecma::ast::ArrowExpr) {}
}
