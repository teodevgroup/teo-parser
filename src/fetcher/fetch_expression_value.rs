use std::error::Error;
use teo_teon::Value;
use crate::ast::availability::Availability;
use crate::ast::expr::{Expression, ExpressionKind};
use crate::r#type::r#type::Type;

pub fn fetch_expression_value<T, E>(
    expression: &Expression,
    namespace_path: &Vec<&str>,
    availability: Availability,
    expect: &Type,
) -> Result<T, E> where T: From<Value>, E: Error {
    fetch_expression_value_kind(&expression.kind, namespace_path, availability, expect)
}

fn fetch_expression_value_kind<T, E>(
    expression_kind: &ExpressionKind,
    namespace_path: &Vec<&str>,
    availability: Availability,
    expect: &Type,
) -> Result<T, E> where T: From<Value>, E: Error {
    match expression_kind {
        ExpressionKind::Group(_) => {}
        ExpressionKind::ArithExpr(_) => {}
        ExpressionKind::NumericLiteral(_) => {}
        ExpressionKind::StringLiteral(_) => {}
        ExpressionKind::RegexLiteral(_) => {}
        ExpressionKind::BoolLiteral(_) => {}
        ExpressionKind::NullLiteral(_) => {}
        ExpressionKind::EnumVariantLiteral(_) => {}
        ExpressionKind::TupleLiteral(_) => {}
        ExpressionKind::ArrayLiteral(_) => {}
        ExpressionKind::DictionaryLiteral(_) => {}
        ExpressionKind::Identifier(_) => {}
        ExpressionKind::ArgumentList(_) => {}
        ExpressionKind::Subscript(_) => {}
        ExpressionKind::Call(_) => {}
        ExpressionKind::Unit(_) => {}
        ExpressionKind::Pipeline(_) => {}
    }
    Ok(T::from(Value::Null))
}