use crate::ast::argument_declaration::{ArgumentDeclaration, ArgumentListDeclaration};
use crate::ast::availability::Availability;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::generics::GenericsDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list::jump_to_definition_in_argument_list;
use crate::definition::jump_to_definition_in_field::jump_to_definition_in_field;
use crate::definition::jump_to_definition_in_type_expr::jump_to_definition_in_type_expr_kind;
use crate::search::search_availability::search_availability;

pub(super) fn jump_to_definition_in_argument_list_declaration(
    schema: &Schema,
    source: &Source,
    argument_list_declaration: &ArgumentListDeclaration,
    generics_declarations: &Vec<&GenericsDeclaration>,
    namespace_path: &Vec<&str>,
    line_col: (usize, usize),
    availability: Availability,
) -> Vec<Definition> {
    for argument_declaration in &argument_list_declaration.argument_declarations {
        if argument_declaration.span.contains_line_col(line_col) {
            return jump_to_definition_in_argument_declaration(
                schema,
                source,
                argument_declaration,
                generics_declarations,
                namespace_path,
                line_col,
                availability,
            );
        }
    }
    vec![]
}

pub(super) fn jump_to_definition_in_argument_declaration(
    schema: &Schema,
    source: &Source,
    argument_declaration: &ArgumentDeclaration,
    generics_declarations: &Vec<&GenericsDeclaration>,
    namespace_path: &Vec<&str>,
    line_col: (usize, usize),
    availability: Availability,
) -> Vec<Definition> {
    if argument_declaration.type_expr.span().contains_line_col(line_col) {
        return jump_to_definition_in_type_expr_kind(
            schema,
            source,
            &argument_declaration.type_expr.kind,
            namespace_path,
            line_col,
            generics_declarations,
            availability
        );
    }
    vec![]
}