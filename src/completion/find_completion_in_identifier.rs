use crate::ast::identifier::Identifier;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_identifier(schema: &Schema, source: &Source, identifier: &Identifier, line_col: (usize, usize), namespace_path: &Vec<&str>) -> Vec<CompletionItem> {
    vec![]
}
