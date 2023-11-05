use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::struct_declaration::StructDeclaration;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_struct_declaration(schema: &Schema, source: &Source, struct_declaration: &StructDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}