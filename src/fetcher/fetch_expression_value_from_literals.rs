// use teo_teon::Value;
// use indexmap::IndexMap;
// use crate::ast::availability::Availability;
// use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, NumericLiteral, RegexLiteral, StringLiteral, TupleLiteral};
// use crate::ast::schema::Schema;
// use crate::ast::source::Source;
// use crate::fetcher::fetch_expression_value::fetch_expression_value;
// use crate::r#type::r#type::Type;
//
// pub(super) fn fetch_expression_value_from_numeric_literal(
//     numeric_literal: &NumericLiteral,
//     namespace_path: &Vec<&str>,
//     availability: Availability,
//     expect: &Type,
// ) -> Result<Option<Value>, String> {
//     Ok(Some(match expect {
//         Type::Int64 => Value::Int64(if let Some(i) = numeric_literal.value.to_int64() {
//             i
//         } else {
//             Err("value is not Int64".to_owned())?
//         }),
//         Type::Int => Value::Int(if let Some(i) = numeric_literal.value.to_int() {
//             i
//         } else {
//             Err("value is not Int".to_owned())?
//         }),
//         Type::Float32 => Value::Float32(if let Some(f) = numeric_literal.value.to_float32() {
//             f
//         } else {
//             Err("value is not Float32".to_owned())?
//         }),
//         Type::Float => Value::Float(if let Some(f) = numeric_literal.value.to_float() {
//             f
//         } else {
//             Err("value is not Float".to_owned())?
//         }),
//         _ => numeric_literal.value.clone(),
//     }))
// }
//
// pub(super) fn fetch_expression_value_from_string_literal<T>(
//     string_literal: &StringLiteral,
//     namespace_path: &Vec<&str>,
//     availability: Availability,
//     expect: &Type,
// ) -> Result<Option<Value>, String> {
//     Ok(Some(Value::String(string_literal.value.clone())))
// }
//
// pub(super) fn fetch_expression_value_from_bool_literal<T>(
//     bool_literal: &BoolLiteral,
//     namespace_path: &Vec<&str>,
//     availability: Availability,
//     expect: &Type,
// ) -> Result<Option<Value>, String> {
//     Ok(Some(Value::Bool(bool_literal.value)))
// }
//
// pub(super) fn fetch_expression_value_from_regex_literal<T>(
//     regex_literal: &RegexLiteral,
//     namespace_path: &Vec<&str>,
//     availability: Availability,
//     expect: &Type,
// ) -> Result<Option<Value>, String> {
//     Ok(Some(Value::Regex(regex_literal.value.clone())))
// }
//
// pub(super) fn fetch_expression_value_from_tuple_literal(
//     schema: &Schema,
//     source: &Source,
//     tuple_literal: &TupleLiteral,
//     namespace_path: &Vec<&str>,
//     availability: Availability,
//     expect: &Type,
// ) -> Result<Option<Value>, String> {
//     let mut result = vec![];
//     let undetermined = Type::Undetermined;
//     for (index, expression) in tuple_literal.expressions.iter().enumerate() {
//         let e = if let Some(e) = expect.as_tuple() {
//             e.get(index).unwrap_or(&undetermined)
//         } else {
//             &undetermined
//         };
//         if let Some(v) = fetch_expression_value(schema, source, expression, namespace_path, availability, e)? {
//             result.push(v);
//         } else {
//             return Ok(None);
//         }
//     }
//     Ok(Some(Value::Tuple(result)))
// }
//
// pub(super) fn fetch_expression_value_from_array_literal(
//     schema: &Schema,
//     source: &Source,
//     array_literal: &ArrayLiteral,
//     namespace_path: &Vec<&str>,
//     availability: Availability,
//     expect: &Type,
// ) -> Result<Option<Value>, String> {
//     let mut result = vec![];
//     let undetermined = Type::Undetermined;
//     let e = expect.as_array().unwrap_or(&undetermined);
//     for expression in array_literal.expressions.iter() {
//         if let Some(v) = fetch_expression_value(schema, source, expression, namespace_path, availability, e)? {
//             result.push(v);
//         } else {
//             return Ok(None);
//         }
//     }
//     Ok(Some(Value::Array(result)))
// }
//
// pub(super) fn fetch_expression_value_from_dictionary_literal(
//     schema: &Schema,
//     source: &Source,
//     dictionary_literal: &DictionaryLiteral,
//     namespace_path: &Vec<&str>,
//     availability: Availability,
//     expect: &Type,
// ) -> Result<Option<Value>, String> {
//     let mut result = IndexMap::new();
//     let undetermined = Type::Undetermined;
//     let string = Type::String;
//     let e = expect.as_dictionary().unwrap_or(&undetermined);
//     for (key_expression, value_expression) in dictionary_literal.expressions.iter() {
//         if let (Some(k), Some(v)) = (
//             fetch_expression_value(schema, source, key_expression, namespace_path, availability, &string)?,
//             fetch_expression_value(schema, source, value_expression, namespace_path, availability, e)?,
//         ) {
//             if !k.is_string() {
//                 return Err("dictionary key is not string".to_owned());
//             }
//             result.insert(k.as_str().unwrap().to_owned(), v);
//         } else {
//             return Ok(None);
//         }
//     }
//     Ok(Some(Value::Dictionary(result)))
// }