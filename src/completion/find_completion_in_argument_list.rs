use crate::ast::argument_list::ArgumentList;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_argument_list(schema: &Schema, source: &Source, argument_list: &ArgumentList, line_col: (usize, usize), namespace_path: &Vec<&str>) -> Vec<CompletionItem> {
    vec![]
}