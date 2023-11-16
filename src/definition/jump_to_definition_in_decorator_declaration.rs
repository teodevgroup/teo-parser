use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list_declaration::jump_to_definition_in_argument_list_declaration;

pub(super) fn jump_to_definition_in_decorator_declaration(schema: &Schema, source: &Source, decorator_declaration: &DecoratorDeclaration, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = decorator_declaration.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = decorator_declaration.define_availability;
    if let Some(argument_list_declaration) = decorator_declaration.argument_list_declaration() {
        if argument_list_declaration.span.contains_line_col(line_col) {
            return jump_to_definition_in_argument_list_declaration(
                schema,
                source,
                argument_list_declaration,
                &decorator_declaration.generics_declaration.as_ref().iter().map(|r| *r).collect(),
                &namespace_path,
                line_col,
                availability
            );
        }
    }
    for variant in &decorator_declaration.variants {
        if let Some(argument_list_declaration) = variant.argument_list_declaration() {
            if argument_list_declaration.span.contains_line_col(line_col) {
                return jump_to_definition_in_argument_list_declaration(
                    schema,
                    source,
                    argument_list_declaration,
                    &variant.generics_declaration.as_ref().iter().map(|r| *r).collect(),
                    &namespace_path,
                    line_col,
                    availability
                );
            }
        }
    }
    vec![]
}