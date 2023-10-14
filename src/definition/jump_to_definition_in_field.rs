use crate::ast::field::Field;
use crate::ast::generics::GenericsDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_decorator::jump_to_definition_in_decorator;
use crate::definition::jump_to_definition_in_type_expr::jump_to_definition_in_type_expr_kind;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn jump_to_definition_in_field<'a>(
    schema: &Schema,
    source: &Source,
    field: &'a Field,
    line_col: (usize, usize),
    generics_declarations: &Vec<&GenericsDeclaration>,
) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = field.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    namespace_path.pop();
    for decorator in &field.decorators {
        if decorator.span.contains_line_col(line_col) {
            return jump_to_definition_in_decorator(schema, source, decorator, &namespace_path, line_col, &top_filter_for_reference_type(field.resolved().class.reference_type()));
        }
    }
    if field.type_expr.span().contains_line_col(line_col) {
        return jump_to_definition_in_type_expr_kind(
            schema,
            source,
            &field.type_expr.kind,
            &namespace_path,
            line_col,
            generics_declarations,
        )
    }
    vec![]
}
