pub mod ast;
pub mod parser;
mod builtin;
pub mod resolver;
pub mod diagnostics;
pub mod utils;
pub(crate) mod definition;

use std::collections::HashMap;
use crate::ast::schema::Schema;
use crate::definition::definition::Definition;
use crate::diagnostics::diagnostics::Diagnostics;
use crate::diagnostics::formatter::format_to_json;
use crate::utils::path::FileUtility;

pub fn parse(
    main: impl AsRef<str>,
    mut file_util: Option<FileUtility>,
    unsaved_files: Option<HashMap<String, String>>,
) -> (Schema, Diagnostics) {
    if file_util.is_none() {
        file_util = Some(FileUtility::default());
    }
    let (schema, mut diagnostics) = parser::parse::parse(
        main,
        file_util.unwrap(),
        unsaved_files,
    );
    resolver::resolve::resolve(&schema, &mut diagnostics);
    (schema, diagnostics)
}

pub fn print_to_terminal(diagnostics: &Diagnostics) {
    diagnostics::printer::print_diagnostics(diagnostics, true);
}

pub fn generate_json_diagnostics(diagnostics: &Diagnostics, include_warnings: bool) -> String {
    format_to_json(diagnostics, include_warnings)
}

pub fn jump_to_definition(schema: &Schema, file_path: &str, line_col: (usize, usize)) -> Vec<Definition> {
    definition::definition::jump_to_definition(schema, file_path, line_col)
}