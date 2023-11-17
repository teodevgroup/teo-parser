use crate::ast::r#enum::Enum;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_enum_declaration(_schema: &Schema, _source: &Source, _enum_declaration: &Enum, _line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}