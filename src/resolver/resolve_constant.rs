use maplit::btreemap;
use crate::ast::constant::{Constant, ConstantResolved};
use crate::r#type::r#type::Type;
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_constant<'a>(constant: &'a Constant, context: &'a ResolverContext<'a>) {
    *constant.actual_availability.borrow_mut() = context.current_availability();
    if let Some(type_expr) = &constant.type_expr {
        resolve_type_expr(type_expr, &vec![], &vec![], &btreemap!{}, context, context.current_availability());
    }
    let undetermined = Type::Undetermined;
    constant.resolve(ConstantResolved {
        expression_resolved: resolve_expression(&constant.expression, context, constant.type_expr.as_ref().map_or(&undetermined, |t| t.resolved()), &btreemap! {}),
    });
}