use teo_teon::value::Value;
use crate::ast::accessible::Accessible;
use crate::ast::expr::{Expression, ExpressionKind};
use crate::ast::group::Group;
use crate::ast::literals::{BoolLiteral, NullLiteral, NumericLiteral, RegExpLiteral, StringLiteral};
use crate::ast::r#type::Type;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_expression<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type) {
    expression.resolve(resolve_expression_kind(&expression.kind, context, expected))
}

pub(super) fn resolve_expression_and_unwrap_value<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type) {
    resolve_expression(expression, context, expected);
    if expression.resolved().is_reference() {
        // do things here
    }
}

pub(super) fn resolve_expression_kind<'a>(expression: &'a ExpressionKind, context: &'a ResolverContext<'a>, expected: &Type) -> Accessible {
    match &expression {
        ExpressionKind::Group(e) => resolve_group(e, context, expected),
        ExpressionKind::ArithExpr(e) => resolve_arith_expr(e, context, expected),
        ExpressionKind::NumericLiteral(n) => Accessible::Value(resolve_numeric_literal(n, context, expected)),
        ExpressionKind::StringLiteral(e) => Accessible::Value(resolve_string_literal(e, context, expected)),
        ExpressionKind::RegExpLiteral(e) => Accessible::Value(resolve_regexp_literal(e, context, expected)),
        ExpressionKind::BoolLiteral(b) => Accessible::Value(resolve_bool_literal(b, context, expected)),
        ExpressionKind::NullLiteral(n) => Accessible::Value(resolve_null_literal(n, context, expected)),
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

fn resolve_group<'a>(group: &Group, context: &'a ResolverContext<'a>, expected: &Type) -> Accessible {
    resolve_expression_kind(&group.expression, context, expected)
}

fn resolve_numeric_literal<'a>(n: &NumericLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    match expected {
        Type::Unresolved => n.value.clone(),
        Type::Int => if n.value.is_any_int() {
            Value::Int(n.value.to_int().unwrap())
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        },
        Type::Int64 => if n.value.is_any_int() {
            Value::Int64(n.value.to_int64().unwrap())
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        },
        Type::Float32 => if n.value.is_any_float() {
            Value::Float32(n.value.to_float32().unwrap())
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        },
        Type::Float => if n.value.is_any_float() {
            Value::Float(n.value.to_float().unwrap())
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        },
        _ => {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        }
    }
}

fn resolve_string_literal<'a>(s: &StringLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    Value::String(s.value.clone())
}

fn resolve_regexp_literal<'a>(r: &RegExpLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    Value::RegExp(r.value.clone())
}

fn resolve_bool_literal<'a>(r: &BoolLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    Value::Bool(r.value)
}

fn resolve_null_literal<'a>(r: &NullLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    Value::Null
}