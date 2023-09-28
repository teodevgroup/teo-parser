use crate::ast::schema::Schema;
use crate::diagnostics::diagnostics::Diagnostics;

pub mod ast;
pub mod parser;
pub mod resolver;
pub mod diagnostics;
pub mod utils;

pub fn parse(main: impl AsRef<str>) -> (Schema, Diagnostics) {
    let (schema, mut diagnostics) = parser::parse::parse(main);
    resolver::resolve::resolve(&schema, &mut diagnostics);
    (schema, diagnostics)
}