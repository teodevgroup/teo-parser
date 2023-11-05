use crate::ast::handler::HandlerGroupDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_handler_group_declaration(schema: &Schema, source: &Source, handler_group_declaration: &HandlerGroupDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}