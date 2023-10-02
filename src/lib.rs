pub mod ast;
pub mod parser;
mod builtin;
pub mod resolver;
pub mod diagnostics;
pub mod utils;

use crate::ast::schema::Schema;
use crate::diagnostics::diagnostics::Diagnostics;
use crate::diagnostics::formatter::format_to_json;
use crate::utils::path::FileUtility;

pub fn parse(main: impl AsRef<str>, mut file_util: Option<FileUtility>) -> (Schema, Diagnostics) {
    if file_util.is_none() {
        file_util = Some(FileUtility::default());
    }
    let (schema, mut diagnostics) = parser::parse::parse(main, file_util.unwrap());
    resolver::resolve::resolve(&schema, &mut diagnostics);
    (schema, diagnostics)
}

pub fn print_to_terminal(diagnostics: &Diagnostics) {
    diagnostics::printer::print_diagnostics(diagnostics, true);
}

pub fn generate_json_diagnostics(diagnostics: &Diagnostics, include_warnings: bool) -> String {
    format_to_json(diagnostics, include_warnings)
}