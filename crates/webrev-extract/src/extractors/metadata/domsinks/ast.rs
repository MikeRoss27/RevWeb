// crates/webrev-extract/src/extractors/metadata/domsinks/ast.rs
//! Small swc AST helpers shared by the taint visitor and module linking.

use swc_core::common::Spanned;
use swc_core::ecma::ast::{AssignTarget, Expr, MemberExpr, MemberProp, Pat};
use swc_core::ecma::visit::{Visit, VisitWith};

/// Build a dotted path for an identifier / plain member chain, e.g.
/// `window.location.hash`. Returns `None` for computed / call / exotic objects.
pub(super) fn member_path(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Ident(id) => Some(id.sym.as_ref().to_owned()),
        Expr::Paren(p) => member_path(&p.expr),
        Expr::Member(m) => member_expr_path(m),
        _ => None,
    }
}

pub(super) fn member_expr_path(m: &MemberExpr) -> Option<String> {
    let obj = member_path(&m.obj)?;
    let MemberProp::Ident(prop) = &m.prop else {
        return None;
    };
    Some(format!("{obj}.{}", prop.sym.as_ref()))
}

pub(super) fn member_prop_name(m: &MemberExpr) -> Option<String> {
    if let MemberProp::Ident(prop) = &m.prop {
        Some(prop.sym.as_ref().to_owned())
    } else {
        None
    }
}

/// Truthiness of a literal `if` condition, so dead arms never contribute flows.
pub(super) fn constant_condition(expr: &Expr) -> Option<bool> {
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
pub(super) fn live_arms(
    statement: &swc_core::ecma::ast::IfStmt,
) -> [Option<&swc_core::ecma::ast::Stmt>; 2] {
    let condition = constant_condition(&statement.test);
    [
        (condition != Some(false)).then_some(&*statement.cons),
        statement.alt.as_deref().filter(|_| condition != Some(true)),
    ]
}

pub(super) fn pat_ident_name(pat: &Pat) -> Option<String> {
    if let Pat::Ident(bi) = pat {
        Some(bi.id.sym.as_ref().to_owned())
    } else {
        None
    }
}

/// Every binding in a parameter/pattern shadows an imported or outer name,
/// even when this lightweight analysis cannot model destructuring values.
pub(super) fn pat_bound_names(pat: &Pat) -> Vec<String> {
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
pub(super) fn assigned_identifiers(target: &AssignTarget) -> Vec<String> {
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
pub(super) fn fn_or_arrow_span(expr: &Expr) -> Option<(usize, usize)> {
    match expr {
        Expr::Fn(f) => Some(span_tuple(f.function.span())),
        Expr::Arrow(a) => Some(span_tuple(a.span())),
        Expr::Paren(p) => fn_or_arrow_span(&p.expr),
        _ => None,
    }
}

pub(super) fn span_tuple(span: swc_core::common::Span) -> (usize, usize) {
    (span.lo.0 as usize, span.hi.0 as usize)
}

pub(super) fn object_is_document(m: &MemberExpr) -> bool {
    member_path(&m.obj).is_some_and(|path| {
        let tail = path
            .strip_prefix("window.")
            .or_else(|| path.strip_prefix("self."))
            .unwrap_or(&path);
        tail == "document"
    })
}
