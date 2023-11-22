use crate::ast::interface::InterfaceDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_field::find_completion_in_field;
use crate::completion::find_completion_in_type_expr::{find_completion_for_empty_type_item, TypeExprFilter};
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;

pub(super) fn find_completion_in_interface(schema: &Schema, source: &Source, interface: &InterfaceDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    for partial_field in interface.partial_fields() {
        if partial_field.span.contains_line_col(line_col) && !partial_field.identifier().span.contains_line_col(line_col) {
            return find_completion_for_empty_type_item(schema, source, &interface.namespace_str_path(), TypeExprFilter::Model, interface.availability());
        }
    }
    for field in interface.fields() {
        if field.span.contains_line_col(line_col) {
            return find_completion_in_field(schema, source, field, line_col, &interface.generics_declaration().into_iter().collect());
        }
    }
    vec![]
}