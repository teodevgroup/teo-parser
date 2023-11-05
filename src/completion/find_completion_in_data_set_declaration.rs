use crate::ast::data_set::DataSet;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_data_set_declaration(schema: &Schema, source: &Source, data_set: &DataSet, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}