use std::collections::{BTreeMap};
use maplit::btreemap;
use path_clean::clean;
use crate::ast::schema::{Schema, SchemaReferences};
use crate::ast::source::Source;
use crate::builtin::STD_TEO;
use crate::diagnostics::diagnostics::Diagnostics;
use crate::parser::parse_builtin_source_file::parse_builtin_source_file;
use crate::parser::parse_source_file::parse_source_file;
use crate::parser::parser_context::ParserContext;
use crate::utils::path::FileUtility;

pub fn parse(
    main: impl AsRef<str>,
    file_util: FileUtility,
    unsaved_files: Option<BTreeMap<String, String>>
) -> (Schema, Diagnostics) {
    let mut parser_context = ParserContext::new(Diagnostics::new(), SchemaReferences::new(), file_util, unsaved_files);
    let mut sources = btreemap!{};
    if !main.as_ref().ends_with("builtin/std.teo") {
        // std library
        let std_source = parse_builtin_source_file(
            STD_TEO,
            "(builtin)std.teo",
            &mut parser_context
        );
        sources.insert(std_source.id, std_source);
    }
    // user schema
    // we don't trust this main path. Clean it.
    let main = clean(main.as_ref()).to_str().unwrap().to_string();
    parse_user_source(
        &mut sources,
        &main,
        &(parser_context.file_util.parent_directory)(&main),
        &mut parser_context
    );
    let schema = Schema { sources, references: parser_context.schema_references_mut().clone() };
    let x = (schema, parser_context.diagnostics().clone());
    x
}

fn parse_user_source(
    sources: &mut BTreeMap<usize, Source>,
    path: impl AsRef<str>,
    base: &str,
    parser_context: &mut ParserContext
) {
    let source = parse_source_file(path, base, parser_context);
    let source_id = source.id;
    sources.insert(source.id, source);
    if parser_context.schema_references_mut().main_source.is_none() {
        parser_context.schema_references_mut().main_source = Some(source_id);
    }
    let import_paths: Vec<String> = sources.get(&source_id).unwrap().imports().iter().map(|i| i.file_path.clone()).collect();
    for import in import_paths {
        if !parser_context.is_source_parsing_or_parsed(&import) {
            if (parser_context.file_util.file_exists)(&import) && (!(parser_context.file_util.file_is_directory)(&import)) {
                parse_user_source(sources, &import, base, parser_context);
            }
        }
    }
}