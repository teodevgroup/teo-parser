use teo_teon::value::Value;
use crate::ast::accessible::Accessible;
use crate::ast::expr::{Expression, ExpressionKind};
use crate::ast::group::Group;
use crate::ast::literals::{BoolLiteral, NullLiteral, NumericLiteral, RegExpLiteral, StringLiteral};
use crate::resolver::resolver_context::ResolverContext;

fn resolve_expression<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>) {
    expression.resolve(resolve_expression_kind(&expression.kind, context))
}

fn resolve_expression_and_unwrap_value<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>) {
    resolve_expression(expression, context);
    if expression.resolved().is_reference() {
        // do things here
    }
}

fn resolve_expression_kind<'a>(expression: &'a ExpressionKind, context: &'a ResolverContext<'a>) -> Accessible {
    match &expression {
        ExpressionKind::Group(e) => resolve_group(e, context),
        ExpressionKind::ArithExpr(e) => resolve_arith_expr(e, context),
        ExpressionKind::NumericLiteral(n) => Accessible::Value(resolve_numeric_literal(n)),
        ExpressionKind::StringLiteral(e) => Accessible::Value(resolve_string_literal(e, context)),
        ExpressionKind::RegExpLiteral(e) => Accessible::Value(resolve_regexp_literal(e, context)),
        ExpressionKind::BoolLiteral(b) => Accessible::Value(resolve_bool_literal(b, context)),
        ExpressionKind::NullLiteral(n) => Accessible::Value(resolve_null_literal(n, context)),
        ExpressionKind::EnumVariantLiteral(_) => {}
        ExpressionKind::TupleLiteral(_) => {}
        ExpressionKind::ArrayLiteral(_) => {}
        ExpressionKind::DictionaryLiteral(_) => {}
        ExpressionKind::Identifier(_) => {}
        ExpressionKind::ArgumentList(_) => {}
        ExpressionKind::Subscript(_) => {}
        ExpressionKind::Unit(_) => {}
        ExpressionKind::Pipeline(_) => {}
    }
}

fn resolve_group<'a>(group: &Group, context: &'a ResolverContext<'a>) -> Accessible {
    resolve_expression_kind(&group.expression, context)
}

fn resolve_numeric_literal<'a>(n: &NumericLiteral, context: &'a ResolverContext<'a>) -> Value {
    n.value.clone()
}

fn resolve_string_literal<'a>(s: &StringLiteral, context: &'a ResolverContext<'a>) -> Value {
    Value::String(s.value.clone())
}

fn resolve_regexp_literal<'a>(r: &RegExpLiteral, context: &'a ResolverContext<'a>) -> Value {
    Value::RegExp(r.value.clone())
}

fn resolve_bool_literal<'a>(r: &BoolLiteral, context: &'a ResolverContext<'a>) -> Value {
    Value::Bool(r.value)
}

fn resolve_null_literal<'a>(r: &NullLiteral, context: &'a ResolverContext<'a>) -> Value {
    Value::Null
}