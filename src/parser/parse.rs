use maplit::btreemap;
use crate::ast::schema::{Schema, SchemaReferences};
use crate::diagnostics::diagnostics::Diagnostics;
use crate::parser::parser_context::ParserContext;

pub fn parse(main: String) -> (Schema, Diagnostics) {
    let mut diagnostics = Diagnostics::new();
    let mut references = SchemaReferences::new();
    let parser_context = ParserContext::new(&mut diagnostics, &mut references);
    let mut sources = btreemap!{};
    let schema = Schema { sources, references };
    (schema, diagnostics)
}