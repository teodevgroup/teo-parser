use std::collections::BTreeMap;
use std::path::Path;
use maplit::btreemap;
use crate::ast::schema::{Schema, SchemaReferences};
use crate::ast::source::Source;
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
    let std_source = parse_builtin_source_file(
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/builtin/std.teo")),
        "(builtin)std.teo",
        &mut parser_context
    );
    sources.insert(std_source.id, std_source);
    // user schema
    parse_user_source(
        &mut sources,
        main,
        &std::env::current_dir().unwrap(),
        &mut parser_context
    );
    let schema = Schema { sources, references };
    (schema, diagnostics)
}

fn parse_user_source(
    sources: &mut BTreeMap<usize, Source>,
    path: impl AsRef<str>,
    base: &Path,
    parser_context: &mut ParserContext
) {
    let source = parse_source_file(path, base, parser_context);
    let source_id = source.id;
    sources.insert(source.id, source);
    let import_paths: Vec<String> = sources.get(&source_id).unwrap().imports().iter().map(|i| i.file_path.to_str().unwrap().to_owned()).collect();
    for import in import_paths {
        if !parser_context.is_source_parsing_or_parsed(&import) {
            parse_user_source(sources, &import, base, parser_context);
        }
    }
}