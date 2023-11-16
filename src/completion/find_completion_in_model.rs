use crate::ast::model::Model;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_decorator::{find_completion_in_decorator, find_completion_in_decorator_with_filter, find_completion_in_empty_decorator};
use crate::completion::find_completion_in_field::find_completion_in_field;
use crate::completion::find_completion_in_handler_group::find_completion_in_handler_declaration;
use crate::completion::find_top_completion_with_filter::find_top_completion_with_filter;
use crate::traits::has_availability::HasAvailability;
use crate::utils::top_filter::top_filter_for_any_model_field_decorators;

pub(super) fn find_completion_in_model(schema: &Schema, source: &Source, model: &Model, line_col: (usize, usize)) -> Vec<CompletionItem> {
    for field in model.fields() {
        if field.span.contains_line_col(line_col) {
            return find_completion_in_field(schema, source, field, line_col, &vec![]);
        }
    }
    let mut namespace_path: Vec<_> = model.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    for decorator in model.decorators() {
        if decorator.span.contains_line_col(line_col) {
            return find_completion_in_decorator(schema, source, decorator, &namespace_path, line_col, ReferenceSpace::ModelDecorator, model.availability());
        }
    }
    for empty_decorator_span in &model.empty_decorator_spans {
        if empty_decorator_span.contains_line_col(line_col) {
            return find_completion_in_empty_decorator(schema, source, &namespace_path, ReferenceSpace::ModelDecorator, model.availability());
        }
    }
    for empty_decorator_span in &model.empty_field_decorator_spans {
        if empty_decorator_span.contains_line_col(line_col) {
            return find_top_completion_with_filter(schema, source, &namespace_path, &vec![], &top_filter_for_any_model_field_decorators(), model.availability());
        }
    }
    for decorator in &model.unattached_field_decorators {
        if decorator.span.contains_line_col(line_col) {
            return find_completion_in_decorator_with_filter(schema, source, decorator, &namespace_path, line_col, &top_filter_for_any_model_field_decorators(), model.availability());
        }
    }
    for handler_declaration in model.handlers() {
        if handler_declaration.span.contains_line_col(line_col) {
            return find_completion_in_handler_declaration(schema, source, handler_declaration, line_col);
        }
    }
    vec![]
}
