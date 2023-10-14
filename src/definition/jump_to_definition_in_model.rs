use crate::ast::model::Model;
use crate::ast::reference::ReferenceType;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_decorator::jump_to_definition_in_decorator;
use crate::definition::jump_to_definition_in_field::jump_to_definition_in_field;
use crate::utils::top_filter::{top_filter_for_any_model_field_decorators, top_filter_for_reference_type};

pub(super) fn jump_to_definition_in_model(schema: &Schema, source: &Source, model: &Model, line_col: (usize, usize)) -> Vec<Definition> {
    for field in &model.fields {
        if field.span.contains_line_col(line_col) {
            return jump_to_definition_in_field(schema, source, field, line_col, &vec![]);
        }
    }
    let mut namespace_path: Vec<_> = model.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    for decorator in &model.decorators {
        if decorator.span.contains_line_col(line_col) {
            return jump_to_definition_in_decorator(schema, source, decorator, &namespace_path, line_col, &top_filter_for_reference_type(ReferenceType::ModelDecorator));
        }
    }
    for decorator in &model.unattached_field_decorators {
        if decorator.span.contains_line_col(line_col) {
            return jump_to_definition_in_decorator(schema, source, decorator, &namespace_path, line_col, &top_filter_for_any_model_field_decorators());
        }
    }
    vec![]
}