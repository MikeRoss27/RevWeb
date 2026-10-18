// crates/webrev-extract/src/extractors/metadata/domsinks/taint/visit.rs
//! swc [`Visit`] traversal driving the [`TaintVisitor`] flow rules.

use super::TaintVisitor;
use crate::extractors::metadata::domsinks::ast::{
    assigned_identifiers, pat_bound_names, pat_ident_name, span_tuple,
};
use std::collections::BTreeMap;
use swc_core::common::Spanned;
use swc_core::ecma::ast::{
    ArrowExpr, AssignExpr, CallExpr, Expr, Function, KeyValueProp, Lit, NewExpr, Pat, PropName,
    VarDeclarator,
};
use swc_core::ecma::visit::{Visit, VisitWith};

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
