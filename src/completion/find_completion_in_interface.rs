use crate::ast::interface::InterfaceDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_field::find_completion_in_field;

pub(super) fn find_completion_in_interface(schema: &Schema, source: &Source, interface: &InterfaceDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    for field in interface.fields() {
        if field.span.contains_line_col(line_col) {
            return find_completion_in_field(schema, source, field, line_col, &interface.generics_declaration().into_iter().collect());
        }
    }
    vec![]
}