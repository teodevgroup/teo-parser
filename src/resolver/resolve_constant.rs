use crate::ast::constant::{Constant, ConstantResolved};
use crate::ast::r#type::Type;
use crate::resolver::resolve_expression::resolve_expression_kind;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_constant<'a>(constant: &'a Constant, context: &'a ResolverContext<'a>) {
    if let Some(type_expr) = &constant.type_expr {
        resolve_type_expr(type_expr, None, None, context);
    }
    let undetermined = Type::Undetermined;
    constant.resolve(ConstantResolved {
        accessible: resolve_expression_kind(&constant.expression, context, constant.type_expr.as_ref().map_or(&undetermined, |t| t.resolved())),
    });
}