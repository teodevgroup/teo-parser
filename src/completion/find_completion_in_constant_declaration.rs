use crate::ast::constant::Constant;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_constant_declaration(schema: &Schema, source: &Source, constant: &Constant, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}