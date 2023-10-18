// use teo_teon::Value;
// use crate::ast::availability::Availability;
// use crate::ast::expr::{Expression, ExpressionKind};
// use crate::ast::schema::Schema;
// use crate::ast::source::Source;
// use crate::fetcher::fetch_expression_value_from_literals::{fetch_expression_value_from_array_literal, fetch_expression_value_from_bool_literal, fetch_expression_value_from_dictionary_literal, fetch_expression_value_from_numeric_literal, fetch_expression_value_from_regex_literal, fetch_expression_value_from_string_literal, fetch_expression_value_from_tuple_literal};
// use crate::r#type::r#type::Type;
//
// pub fn fetch_expression_value(
//     schema: &Schema,
//     source: &Source,
//     expression: &Expression,
//     namespace_path: &Vec<&str>,
//     availability: Availability,
//     expect: &Type,
// ) -> Result<Option<Value>, String> {
//     fetch_expression_value_kind(schema, source, &expression.kind, namespace_path, availability, expect)
// }
//
// fn fetch_expression_value_kind(
//     schema: &Schema,
//     source: &Source,
//     expression_kind: &ExpressionKind,
//     namespace_path: &Vec<&str>,
//     availability: Availability,
//     expect: &Type,
// ) -> Result<Option<Value>, String> {
//     match expression_kind {
//         ExpressionKind::Group(g) => fetch_expression_value_kind(schema, source, &g.expression.kind, namespace_path, availability, expect),
//         ExpressionKind::ArithExpr(a) => {}
//         ExpressionKind::NumericLiteral(n) => fetch_expression_value_from_numeric_literal(n, namespace_path, availability, expect),
//         ExpressionKind::StringLiteral(s) => fetch_expression_value_from_string_literal(s, namespace_path, availability, expect),
//         ExpressionKind::RegexLiteral(r) => fetch_expression_value_from_regex_literal(r, namespace_path, availability, expect),
//         ExpressionKind::BoolLiteral(b) => fetch_expression_value_from_bool_literal(b, namespace_path, availability, expect),
//         ExpressionKind::NullLiteral(_) => Ok(Some(Value::Null)),
//         ExpressionKind::EnumVariantLiteral(_) => {}
//         ExpressionKind::TupleLiteral(t) => fetch_expression_value_from_tuple_literal(schema, source, t, namespace_path, availability, expect),
//         ExpressionKind::ArrayLiteral(a) => fetch_expression_value_from_array_literal(schema, source, a, namespace_path, availability, expect),
//         ExpressionKind::DictionaryLiteral(d) => fetch_expression_value_from_dictionary_literal(schema, source, d, namespace_path, availability, expect),
//         ExpressionKind::Identifier(i) => {}
//         ExpressionKind::ArgumentList(_) => unreachable!(),
//         ExpressionKind::Subscript(_) => unreachable!(),
//         ExpressionKind::Call(_) => unreachable!(),
//         ExpressionKind::Unit(u) => {}
//         ExpressionKind::Pipeline(p) => {}
//     }
//     Ok(Some(Value::Null))
// }