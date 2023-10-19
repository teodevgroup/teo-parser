use crate::ast::availability::Availability;
use crate::ast::function_declaration::FunctionDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::struct_declaration::StructDeclaration;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list_declaration::jump_to_definition_in_argument_list_declaration;
use crate::definition::jump_to_definition_in_type_expr::jump_to_definition_in_type_expr_kind;
use crate::search::search_availability::search_availability;

pub(super) fn jump_to_definition_in_struct_declaration(schema: &Schema, source: &Source, struct_declaration: &StructDeclaration, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = struct_declaration.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = struct_declaration.define_availability;
    for function_declaration in &struct_declaration.function_declarations {
        if function_declaration.span.contains_line_col(line_col) {
            return jump_to_definition_in_function_declaration(
                schema,
                source,
                struct_declaration,
                function_declaration,
                &namespace_path,
                line_col,
                availability,
            );
        }
    }
    vec![]
}

pub(super) fn jump_to_definition_in_function_declaration(
    schema: &Schema,
    source: &Source,
    struct_declaration: &StructDeclaration,
    function_declaration: &FunctionDeclaration,
    namespace_path: &Vec<&str>,
    line_col: (usize, usize),
    availability: Availability
) -> Vec<Definition> {
    let mut generics = vec![];
    if let Some(gen) = &struct_declaration.generics_declaration {
        generics.push(gen);
    }
    if let Some(gen) = &function_declaration.generics_declaration {
        generics.push(gen);
    }
    if let Some(argument_list_declaration) = &function_declaration.argument_list_declaration {
        return jump_to_definition_in_argument_list_declaration(
            schema,
            source,
            argument_list_declaration,
            &generics,
            namespace_path,
            line_col,
            availability,
        );
    }
    vec![]
}