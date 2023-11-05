use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_field::find_completion_in_field;

pub(super) fn find_completion_in_config_declaration(schema: &Schema, source: &Source, config_declaration: &ConfigDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    for field in &config_declaration.fields {
        if field.span.contains_line_col(line_col) {
            return find_completion_in_field(schema, source, field, line_col, &vec![]);
        }
    }
    vec![]
}