use crate::ast::identifier::Identifier;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_identifier(_schema: &Schema, _source: &Source, _identifier: &Identifier, _line_col: (usize, usize), _namespace_path: &Vec<&str>) -> Vec<CompletionItem> {
    vec![]
}
