use crate::ast::interface::InterfaceDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_interface(schema: &Schema, source: &Source, interface: &InterfaceDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}