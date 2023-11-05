use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::use_middlewares::UseMiddlewaresBlock;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_use_middleware_block(schema: &Schema, source: &Source, use_middleware_block: &UseMiddlewaresBlock, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}