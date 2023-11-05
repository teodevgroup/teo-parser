use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_decorator_declaration(schema: &Schema, source: &Source, decorator_declaration: &DecoratorDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}