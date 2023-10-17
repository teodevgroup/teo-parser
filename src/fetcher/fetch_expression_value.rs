use std::error::Error;
use teo_teon::Value;
use crate::ast::availability::Availability;
use crate::ast::expr::Expression;

pub fn fetch_expression_value<T, E>(
    expression: &Expression,
    namespace_path: &Vec<&str>,
    availability: Availability,
) -> Result<T, E> where T: From<Value>, E: Error {
    Ok(T::from(Value::Null))
}