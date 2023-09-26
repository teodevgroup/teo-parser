use maplit::btreemap;
use crate::ast::schema::{Schema, SchemaReferences};
use crate::diagnostics::diagnostics::Diagnostics;
use crate::parser::parse_builtin_source_file::parse_builtin_source_file;
use crate::parser::parse_source_file::parse_source_file;
use crate::parser::parser_context::ParserContext;

pub fn parse(main: impl AsRef<str>) -> (Schema, Diagnostics) {
    let mut diagnostics = Diagnostics::new();
    let mut references = SchemaReferences::new();
    let mut parser_context = ParserContext::new(&mut diagnostics, &mut references);
    let mut sources = btreemap!{};
    // std library
    let std_schema = parse_builtin_source_file(
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/builtin/std.teo")),
        "(builtin)std.teo",
        &mut parser_context
    );
    sources.insert(std_schema.id, std_schema);
    // user schema
    let main_schema = parse_source_file(
        main,
        &std::env::current_dir().unwrap(),
        &mut parser_context
    );
    sources.insert(main_schema.id, main_schema);
    let schema = Schema { sources, references };
    (schema, diagnostics)
}