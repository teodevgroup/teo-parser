use crate::ast::availability::Availability;
use crate::ast::middleware::MiddlewareDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list_declaration::jump_to_definition_in_argument_list_declaration;
use crate::search::search_availability::search_availability;

pub(super) fn jump_to_definition_in_middleware_declaration(schema: &Schema, source: &Source, middleware: &MiddlewareDeclaration, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = middleware.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = search_availability(schema, source, &namespace_path);
    if let Some(argument_list_declaration) = &middleware.argument_list_declaration {
        return jump_to_definition_in_argument_list_declaration(
            schema,
            source,
            argument_list_declaration,
            &vec![],
            &namespace_path,
            line_col,
            availability
        );
    }
    vec![]
}