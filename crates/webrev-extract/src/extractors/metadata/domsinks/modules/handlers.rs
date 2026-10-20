//! Cross-file `postMessage` handler linking: `window.addEventListener('message',
//! imported)` in one module, where `imported` is a plain identifier imported
//! (named or default) from another module's top-level `function` declaration.
//! The declaration's body is then analyzed as a `message` handler (its first
//! parameter seeded as `event.data`, exactly as the same-file case in
//! [`crate::extractors::metadata::domsinks::taint::TaintVisitor::register_addeventlistener`]
//! does), using the existing [`super::TaintVisitor::handler_spans`] mechanism.
//!
//! Deliberately NOT handled (left for a future, explicitly scoped extension):
//! - a computed registration (`addEventListener('message', table[key])`) or any
//!   non-identifier expression;
//! - a namespace member (`addEventListener('message', ns.handler)`);
//! - re-export chains: the imported identifier must resolve directly to a
//!   named/default import whose source module declares the function, not
//!   through a barrel `export {..} from` hop;
//! - a handler bound to a `const`/arrow or function *expression* in the target
//!   module (only an actual top-level `function` declaration, named or
//!   default-exported, is summarized);
//! - non-ES-module scripts (classic `<script>` tags without `import`/`export`).
use super::{
    export_name, exported_locals, resolve, Decl, ImportSpecifier, ModuleDecl, ModuleItem,
    ParsedModule, Stmt,
};
use crate::extractors::metadata::domsinks::ast::{member_prop_name, span_tuple};
use swc_core::common::Spanned;
use swc_core::ecma::ast::{CallExpr, Callee, DefaultDecl, Expr, Lit};
use swc_core::ecma::visit::{Visit, VisitWith};

/// Identifiers passed as the handler argument to `addEventListener('message',
/// <ident>)` anywhere in a module (including inside its own functions).
#[derive(Default)]
pub(super) struct MessageHandlerIdents(pub(super) Vec<String>);

impl Visit for MessageHandlerIdents {
    fn visit_call_expr(&mut self, call: &CallExpr) {
        if let Some(name) = message_handler_ident(call) {
            self.0.push(name);
        }
        call.visit_children_with(self);
    }
}

fn message_handler_ident(call: &CallExpr) -> Option<String> {
    let Callee::Expr(callee) = &call.callee else {
        return None;
    };
    let is_add_event_listener = match &**callee {
        Expr::Member(m) => member_prop_name(m).as_deref() == Some("addEventListener"),
        Expr::Ident(id) => id.sym.as_ref() == "addEventListener",
        _ => false,
    };
    if !is_add_event_listener {
        return None;
    }
    let first = call.args.first()?;
    if first.spread.is_some() {
        return None;
    }
    let Expr::Lit(Lit::Str(s)) = &*first.expr else {
        return None;
    };
    if &*s.value.to_string_lossy() != "message" {
        return None;
    }
    let handler = call.args.get(1)?;
    if handler.spread.is_some() {
        return None;
    }
    match &*handler.expr {
        Expr::Ident(id) => Some(id.sym.to_string()),
        _ => None,
    }
}

/// Resolve a local binding name to the `(module url, exported name)` it was
/// imported from, for a plain named or default import specifier only
/// (namespace imports are out of scope here).
pub(super) fn imported_identifier(parsed: &ParsedModule, name: &str) -> Option<(String, String)> {
    for item in &parsed.module.body {
        let ModuleItem::ModuleDecl(ModuleDecl::Import(import)) = item else {
            continue;
        };
        if import.type_only || import.with.is_some() {
            continue;
        }
        let url = resolve(&parsed.url, &import.src.value.to_string_lossy())?;
        for specifier in &import.specifiers {
            match specifier {
                ImportSpecifier::Named(named)
                    if !named.is_type_only && named.local.sym.as_ref() == name =>
                {
                    let exported = named
                        .imported
                        .as_ref()
                        .map_or_else(|| named.local.sym.to_string(), export_name);
                    return Some((url, exported));
                }
                ImportSpecifier::Default(default) if default.local.sym.as_ref() == name => {
                    return Some((url, "default".to_owned()));
                }
                _ => {}
            }
        }
    }
    None
}

/// Byte-range span of a top-level `function` declaration exported under
/// `exported_name`: `export function f(){}`, `function f(){} export {f}` /
/// `export {f as name}`, or `export default function f(){}`
/// (including the anonymous default-export form).
pub(super) fn exported_function(
    parsed: &ParsedModule,
    exported_name: &str,
) -> Option<(usize, usize)> {
    for item in &parsed.module.body {
        if let ModuleItem::ModuleDecl(ModuleDecl::ExportDecl(export)) = item {
            if let Decl::Fn(function) = &export.decl {
                if function.ident.sym.as_ref() == exported_name {
                    return Some(span_tuple(function.function.span()));
                }
            }
        }
    }
    if exported_name == "default" {
        return parsed.module.body.iter().find_map(|item| {
            let ModuleItem::ModuleDecl(ModuleDecl::ExportDefaultDecl(default)) = item else {
                return None;
            };
            let DefaultDecl::Fn(function) = &default.decl else {
                return None;
            };
            Some(span_tuple(function.function.span()))
        });
    }
    // `function f(){} ... export {f as exported_name}`: the re-exported local
    // must itself be a plain top-level function declaration.
    for (exported, local) in exported_locals(&parsed.module) {
        if exported != exported_name {
            continue;
        }
        for item in &parsed.module.body {
            if let ModuleItem::Stmt(Stmt::Decl(Decl::Fn(function))) = item {
                if function.ident.sym.as_ref() == local {
                    return Some(span_tuple(function.function.span()));
                }
            }
        }
    }
    None
}
