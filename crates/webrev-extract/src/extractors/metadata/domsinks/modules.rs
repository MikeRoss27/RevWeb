//! Bounded ES-module linking. Explicit named/default values, `ns.name` members of
//! namespace imports, `export {..} from` / `export * from` re-exports and named
//! function summaries cross file boundaries; unresolved imports, dynamic imports,
//! computed namespace members and cycles without a concrete source never invent
//! a flow.
use super::ast::{live_arms, pat_ident_name};
use super::taint::{ImportedFunction, TaintVisitor};
use super::{
    BytePos, Confidence, ContentKind, DomSinkExtractor, EsSyntax, ExtractInput, FileName, Finding,
    FindingKind, Lrc, Parser, Provenance, Source, SourceMap, StringInput, Syntax, VisitWith,
};
use std::collections::{BTreeMap, BTreeSet};
use swc_core::ecma::ast::{
    Decl, ExportSpecifier, Expr, IfStmt, ImportSpecifier, Module, ModuleDecl, ModuleExportName,
    ModuleItem, Stmt, VarDecl, VarDeclKind,
};
use url::Url;

mod functions;
mod links;
use functions::{function_exports, local_functions};

/// Limits also apply to the pipeline's retained JavaScript inputs.
pub const MAX_MODULES: usize = 128;
pub const MAX_MODULE_BYTES: usize = 512 * 1024;
pub const MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;
const MAX_LINK_PASSES: usize = 8;

#[derive(Clone, PartialEq, Eq)]
struct ExportValue {
    origin: String,
    locations: BTreeSet<String>,
    function: Option<ImportedFunction>,
}

struct ParsedModule {
    url: Url,
    module: Module,
}

type Exports = BTreeMap<(String, String), ExportValue>;

fn export_name(name: &ModuleExportName) -> String {
    match name {
        ModuleExportName::Ident(id) => id.sym.to_string(),
        ModuleExportName::Str(value) => value.value.to_string_lossy().into_owned(),
    }
}

fn parse(input: &ExtractInput) -> Option<ParsedModule> {
    if input.kind != ContentKind::JavaScript || input.body.len() > MAX_MODULE_BYTES {
        return None;
    }
    let url = Url::parse(input.url.as_deref()?).ok()?;
    let cm: Lrc<SourceMap> = Lrc::default();
    let fm = cm.new_source_file(Lrc::new(FileName::Anon), input.body.clone());
    let len = u32::try_from(fm.src.len()).ok()?;
    let mut parser = Parser::new(
        Syntax::Es(EsSyntax {
            jsx: true,
            ..EsSyntax::default()
        }),
        StringInput::new(&fm.src, BytePos(0), BytePos(len)),
        None,
    );
    let module = crate::js_parse::guarded(|| parser.parse_module())?;
    if !parser.take_errors().is_empty() {
        return None;
    }
    Some(ParsedModule { url, module })
}

/// URL resolution follows explicit browser module specifiers; bare package
/// specifiers require an import map, which this analysis does not model.
fn resolve(base: &Url, specifier: &str) -> Option<String> {
    if !(specifier.starts_with("./")
        || specifier.starts_with("../")
        || specifier.starts_with('/')
        || Url::parse(specifier).is_ok())
    {
        return None;
    }
    base.join(specifier).ok().map(|url| url.to_string())
}

fn seed_imports(
    parsed: &ParsedModule,
    exports: &Exports,
) -> (TaintVisitor, BTreeMap<String, ExportValue>) {
    let mut visitor = TaintVisitor::new();
    let mut imports = BTreeMap::new();
    for item in &parsed.module.body {
        let ModuleItem::ModuleDecl(ModuleDecl::Import(import)) = item else {
            continue;
        };
        if import.type_only || import.with.is_some() {
            continue;
        }
        let Some(url) = resolve(&parsed.url, &import.src.value.to_string_lossy()) else {
            continue;
        };
        for specifier in &import.specifiers {
            if let ImportSpecifier::Namespace(namespace) = specifier {
                // `ns.name` is seeded as a dotted key for every known export.
                let local = namespace.local.sym.to_string();
                let members = exports
                    .range((url.clone(), String::new())..)
                    .take_while(|((module, _), _)| *module == url);
                for ((_, name), value) in members {
                    let key = format!("{local}.{name}");
                    seed_value(&mut visitor, &key, value);
                    imports.insert(key, value.clone());
                }
                continue;
            }
            let (local, exported) = match specifier {
                ImportSpecifier::Named(named) if !named.is_type_only => (
                    named.local.sym.to_string(),
                    named
                        .imported
                        .as_ref()
                        .map_or_else(|| named.local.sym.to_string(), export_name),
                ),
                ImportSpecifier::Default(default) => {
                    (default.local.sym.to_string(), "default".to_owned())
                }
                _ => continue,
            };
            if let Some(value) = exports.get(&(url.clone(), exported)) {
                seed_value(&mut visitor, &local, value);
                imports.insert(local, value.clone());
            }
        }
    }
    visitor.module_calls_only = true;
    (visitor, imports)
}

fn seed_value(visitor: &mut TaintVisitor, key: &str, value: &ExportValue) {
    if let Some(function) = &value.function {
        visitor.scopes[0].insert(key.to_owned(), None);
        visitor
            .imported_functions
            .insert(key.to_owned(), function.clone());
    } else {
        visitor.insert_var(key.to_owned(), value.origin.clone());
    }
}

fn exported_locals(module: &Module) -> Vec<(String, String)> {
    let mut bindings = Vec::new();
    for item in &module.body {
        match item {
            ModuleItem::ModuleDecl(ModuleDecl::ExportNamed(named))
                if named.src.is_none() && !named.type_only =>
            {
                for specifier in &named.specifiers {
                    if let ExportSpecifier::Named(named) = specifier {
                        if !named.is_type_only {
                            bindings.push((
                                named
                                    .exported
                                    .as_ref()
                                    .map_or_else(|| export_name(&named.orig), export_name),
                                export_name(&named.orig),
                            ));
                        }
                    }
                }
            }
            ModuleItem::ModuleDecl(ModuleDecl::ExportDecl(export)) => {
                if let Decl::Fn(function) = &export.decl {
                    let name = function.ident.sym.to_string();
                    bindings.push((name.clone(), name));
                }
                if let Decl::Var(var) = &export.decl {
                    for decl in &var.decls {
                        if let Some(name) = pat_ident_name(&decl.name) {
                            bindings.push((name.clone(), name));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    bindings
}

fn locations(
    origin: &str,
    parsed: &ParsedModule,
    imports: &BTreeMap<String, ExportValue>,
) -> BTreeSet<String> {
    let mut locations = BTreeSet::from([parsed.url.to_string()]);
    for value in imports.values() {
        if !value.origin.is_empty()
            && (origin == value.origin
                || origin
                    .strip_prefix(&value.origin)
                    .is_some_and(|tail| tail.starts_with(" -> ")))
        {
            locations.extend(value.locations.iter().cloned());
        }
    }
    locations
}

fn declare(visitor: &mut TaintVisitor, var: &VarDecl) {
    for decl in &var.decls {
        if let Some(name) = pat_ident_name(&decl.name) {
            let origin = decl
                .init
                .as_deref()
                .and_then(|value| visitor.classify(value))
                .map(|(origin, _)| origin);
            visitor.scopes[0].insert(name, origin);
        }
    }
}

/// Apply one statement inside a top-level `if`. Only assignments, `var`
/// declarations (which hoist to module scope), blocks and nested `if`s are
/// understood; anything else makes the whole summary unavailable (`None`).
fn apply_branch(visitor: &mut TaintVisitor, stmt: &Stmt) -> Option<()> {
    match stmt {
        Stmt::Expr(expression) => {
            if let Expr::Assign(assign) = &*expression.expr {
                visitor.assign_var(assign);
            }
        }
        Stmt::Decl(Decl::Var(var)) if var.kind == VarDeclKind::Var => declare(visitor, var),
        Stmt::Block(block) => {
            for inner in &block.stmts {
                apply_branch(visitor, inner)?;
            }
        }
        Stmt::If(inner) => apply_if(visitor, inner)?,
        Stmt::Empty(_) => {}
        _ => return None,
    }
    Some(())
}

/// May-taint merge of both arms: a binding tainted before the `if` or in either
/// arm stays tainted, so a conditional overwrite never hides a possible flow.
/// The condition itself is not evaluated.
fn apply_if(visitor: &mut TaintVisitor, statement: &IfStmt) -> Option<()> {
    let base = visitor.scopes[0].clone();
    let mut merged = base.clone();
    for arm in live_arms(statement) {
        visitor.scopes[0] = base.clone();
        if let Some(arm) = arm {
            apply_branch(visitor, arm)?;
        }
        for (name, origin) in &visitor.scopes[0] {
            let slot = merged.entry(name.clone()).or_insert(None);
            if slot.is_none() {
                slot.clone_from(origin);
            }
        }
    }
    visitor.scopes[0] = merged;
    Some(())
}

/// Own exports win over named re-exports, which win over `export *`.
fn summarize(parsed: &ParsedModule, exports: &Exports) -> BTreeMap<String, ExportValue> {
    let mut result = links::star_reexports(parsed, exports);
    result.extend(links::named_reexports(parsed, exports));
    result.extend(summarize_local(parsed, exports));
    result
}

fn summarize_local(parsed: &ParsedModule, exports: &Exports) -> BTreeMap<String, ExportValue> {
    let (mut visitor, imports) = seed_imports(parsed, exports);
    // Declarations hoist, so same-module helpers are callable from any
    // initialization statement.
    for (name, function) in local_functions(parsed, &visitor, &imports) {
        visitor.scopes[0].entry(name.clone()).or_insert(None);
        visitor.imported_functions.entry(name).or_insert(function);
    }
    let mut default_export = None;
    for item in &parsed.module.body {
        let declaration = match item {
            ModuleItem::Stmt(Stmt::Decl(Decl::Var(var))) => Some(var),
            ModuleItem::ModuleDecl(ModuleDecl::ExportDecl(export)) => match &export.decl {
                Decl::Var(var) => Some(var),
                _ => None,
            },
            ModuleItem::ModuleDecl(ModuleDecl::ExportDefaultExpr(default)) => {
                default_export = visitor
                    .classify(&default.expr)
                    .map(|(origin, _)| ExportValue {
                        locations: locations(&origin, parsed, &imports),
                        origin,
                        function: None,
                    });
                None
            }
            ModuleItem::Stmt(Stmt::Expr(expression)) => {
                if let Expr::Assign(assign) = &*expression.expr {
                    visitor.assign_var(assign);
                }
                None
            }
            ModuleItem::Stmt(Stmt::If(statement)) => {
                if apply_if(&mut visitor, statement).is_none() {
                    return BTreeMap::new();
                }
                None
            }
            // Other control flow stays unsupported: it could leak block-local
            // bindings or hide a definite overwrite of an exported value.
            ModuleItem::Stmt(
                Stmt::Block(_)
                | Stmt::For(_)
                | Stmt::ForIn(_)
                | Stmt::ForOf(_)
                | Stmt::While(_)
                | Stmt::DoWhile(_)
                | Stmt::Switch(_)
                | Stmt::Try(_)
                | Stmt::With(_)
                | Stmt::Labeled(_),
            ) => return BTreeMap::new(),
            _ => None,
        };
        if let Some(var) = declaration {
            declare(&mut visitor, var);
        }
    }
    let mut result = BTreeMap::new();
    for (exported, local) in exported_locals(&parsed.module) {
        if let Some(origin) = visitor.lookup(&local) {
            result.insert(
                exported,
                ExportValue {
                    locations: locations(&origin, parsed, &imports),
                    origin,
                    function: None,
                },
            );
        }
    }
    let functions = function_exports(parsed, &visitor, &imports);
    for (name, function) in functions {
        result.insert(name, function);
    }
    if let Some(value) = default_export {
        result.insert("default".to_owned(), value);
    }
    result
}

/// Single-file analysis with summaries of the top-level function declarations,
/// so a tainted argument or return value crosses a call to a local function.
/// Arrow and function expressions, methods and nested declarations are not
/// summarized.
pub(super) fn analyze_standalone(module: Module) -> super::TaintResult {
    let Ok(url) = Url::parse("file:///standalone.js") else {
        return (Vec::new(), Vec::new());
    };
    let parsed = ParsedModule { url, module };
    let mut visitor = TaintVisitor::new();
    for (name, function) in local_functions(&parsed, &visitor, &BTreeMap::new()) {
        visitor.scopes[0].entry(name.clone()).or_insert(None);
        visitor.imported_functions.insert(name, function);
    }
    parsed.module.visit_with(&mut visitor);
    (visitor.traces, visitor.traced_spans)
}

impl DomSinkExtractor {
    /// Extract additional static candidates across explicit ES-module imports.
    /// Inputs must belong to one session and retain their fetched final URLs.
    /// Files remain separate ASTs. Work is capped at 128 modules, 512 KiB per
    /// module, 8 MiB total and eight linking passes. Inputs beyond those caps
    /// remain covered by ordinary single-file extraction. No network I/O or
    /// runtime execution occurs; a candidate is never `Confirmed`.
    pub fn retain_module_input(inputs: &mut Vec<ExtractInput>, input: ExtractInput) {
        if input.kind == ContentKind::JavaScript
            && input.url.is_some()
            && (input.body.contains("import") || input.body.contains("export"))
            && input.body.len() <= MAX_MODULE_BYTES
            && inputs.len() < MAX_MODULES
            && inputs.iter().map(|item| item.body.len()).sum::<usize>() + input.body.len()
                <= MAX_TOTAL_BYTES
        {
            inputs.push(input);
        }
    }

    /// Analyze a bounded collection of fetched ES modules. See
    /// [`Self::retain_module_input`] for incremental input collection.
    #[must_use]
    pub fn extract_modules(inputs: &[ExtractInput]) -> Vec<Finding> {
        let Some(session) = inputs.first().map(|input| input.session_id) else {
            return Vec::new();
        };
        // Apply every bound before URL counting, substring scans and parsing.
        // Rejected parses still consume their byte budget.
        let mut bytes = 0usize;
        let candidates: Vec<_> = inputs
            .iter()
            .take(MAX_MODULES)
            .filter(|input| {
                if input.session_id != session
                    || input.body.len() > MAX_MODULE_BYTES
                    || bytes.saturating_add(input.body.len()) > MAX_TOTAL_BYTES
                {
                    return false;
                }
                bytes += input.body.len();
                true
            })
            .collect();
        if !candidates.iter().any(|input| input.body.contains("import")) {
            return Vec::new();
        }
        let mut url_counts = BTreeMap::new();
        for input in &candidates {
            if let Some(url) = input.url.as_deref().and_then(|url| Url::parse(url).ok()) {
                *url_counts.entry(url.to_string()).or_insert(0usize) += 1;
            }
        }
        let parsed: Vec<_> = candidates
            .into_iter()
            .filter_map(|input| {
                let parsed = parse(input)?;
                // Conflicting versions of one URL cannot be linked safely.
                (url_counts.get(parsed.url.as_str()) == Some(&1)).then_some(parsed)
            })
            .collect();
        let mut exports = Exports::new();
        for _ in 0..MAX_LINK_PASSES {
            let mut next = Exports::new();
            for module in &parsed {
                for (name, value) in summarize(module, &exports) {
                    next.insert((module.url.to_string(), name), value);
                }
            }
            if exports == next {
                break;
            }
            exports = next;
        }
        let mut findings = Vec::new();
        for module in &parsed {
            let (mut visitor, imports) = seed_imports(module, &exports);
            if imports.is_empty() {
                continue;
            }
            module.module.visit_with(&mut visitor);
            let mut local = TaintVisitor::new();
            module.module.visit_with(&mut local);
            let local_traces: BTreeSet<_> =
                local.traces.into_iter().map(|(value, _)| value).collect();
            let mut seen = BTreeSet::new();
            for (value, _) in visitor.traces {
                if local_traces.contains(&value) || !seen.insert(value.clone()) {
                    continue;
                }
                let origin = value
                    .strip_prefix("DOM XSS: ")
                    .and_then(|flow| flow.rsplit_once(" -> "))
                    .map_or("", |(origin, _)| origin);
                let mut finding = Finding::new(
                    session,
                    FindingKind::Config,
                    None,
                    value.clone(),
                    Confidence::Medium,
                    Provenance::new(Source::JsAst, Some(module.url.to_string())),
                );
                finding.status = webrev_core::FindingStatus::Suspicious;
                finding.detectors.push("dom-sinks-modules".to_owned());
                "Static source-to-sink candidate linked through explicit ES-module value imports or direct calls to summarized exported functions. Runtime reachability, sanitizer context and exploitability remain unverified.".clone_into(&mut finding.justification);
                let mut evidence_locations = locations(origin, module, &imports);
                if let Some(extra) = visitor.linked_trace_locations.get(&value) {
                    evidence_locations.extend(extra.iter().cloned());
                }
                finding.provenances = evidence_locations
                    .into_iter()
                    .map(|url| Provenance::new(Source::JsAst, Some(url)))
                    .collect();
                findings.push(finding);
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_links;
