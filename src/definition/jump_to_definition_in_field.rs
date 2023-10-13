use crate::ast::field::Field;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_decorator::jump_to_definition_in_decorator;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn jump_to_definition_in_field<'a>(schema: &Schema, source: &Source, field: &'a Field, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = field.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    namespace_path.pop();
    for decorator in &field.decorators {
        if decorator.span.contains_line_col(line_col) {
            return jump_to_definition_in_decorator(schema, source, decorator, &namespace_path, line_col, &top_filter_for_reference_type(field.resolved().class.reference_type()));
        }
    }
    vec![]
}
