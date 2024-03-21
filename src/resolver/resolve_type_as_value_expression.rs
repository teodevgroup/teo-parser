use maplit::btreemap;
use crate::ast::type_as_value_expression::TypeAsValueExpression;
use crate::expr::ExprInfo;
use crate::r#type::Type;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::resolved::Resolve;
use crate::value::Value;

pub(super) fn resolve_type_as_value_expression<'a>(
    type_as_value_expression: &'a TypeAsValueExpression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    resolve_type_expr(
        type_as_value_expression.type_expr(),
        &vec![],
        &vec![],
        &btreemap! {},
        context,
        context.current_availability(),
    );
    let t = type_as_value_expression.type_expr().resolved();
    ExprInfo {
        r#type: Type::Type,
        value: Some(Value::Type(t.clone())),
        reference_info: None,
    }
}