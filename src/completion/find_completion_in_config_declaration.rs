use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_config_declaration(schema: &Schema, source: &Source, config_declaration: &ConfigDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}