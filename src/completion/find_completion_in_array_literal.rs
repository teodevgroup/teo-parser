use crate::ast::literals::ArrayLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_array_literal(schema: &Schema, source: &Source, array_literal: &ArrayLiteral, line_col: (usize, usize), namespace_path: &Vec<&str>) -> Vec<CompletionItem> {
    vec![]
}
