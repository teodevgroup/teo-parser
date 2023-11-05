use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_unit(schema: &Schema, source: &Source, unit: &Unit, line_col: (usize, usize), namespace_path: &Vec<&str>) -> Vec<CompletionItem> {
    vec![]
}
