use maplit::btreemap;
use crate::ast::constant_declaration::{ConstantDeclaration};
use crate::r#type::r#type::Type;
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_constant_references<'a>(constant: &'a ConstantDeclaration, context: &'a ResolverContext<'a>) {
    if constant.is_resolved() { return; }
    *constant.actual_availability.borrow_mut() = context.current_availability();
    if let Some(type_expr) = constant.type_expr() {
        resolve_type_expr(type_expr, &vec![], &vec![], &btreemap!{}, context, context.current_availability());
    }
    let undetermined = Type::Undetermined;
    context.push_dependency(constant.path.clone());
    let resolved = resolve_expression(constant.expression(), context, constant.type_expr().map_or(&undetermined, |t| t.resolved()), &btreemap! {});
    constant.resolve(resolved);
    context.pop_dependency();
}

pub(super) fn resolve_constant_check<'a>(constant: &'a ConstantDeclaration, context: &'a ResolverContext<'a>) {
    if !constant.is_resolved() {

    }
}