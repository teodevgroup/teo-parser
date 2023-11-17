use crate::ast::data_set::DataSet;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_data_set_declaration(_schema: &Schema, _source: &Source, _data_set: &DataSet, _line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}