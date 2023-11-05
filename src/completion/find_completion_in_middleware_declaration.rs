use crate::ast::middleware::MiddlewareDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_middleware_declaration(schema: &Schema, source: &Source, middleware_declaration: &MiddlewareDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}