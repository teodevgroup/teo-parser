use crate::ast::literals::TupleLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_tuple_literal(schema: &Schema, source: &Source, tuple_literal: &TupleLiteral, line_col: (usize, usize), namespace_path: &Vec<&str>) -> Vec<CompletionItem> {
    vec![]
}
