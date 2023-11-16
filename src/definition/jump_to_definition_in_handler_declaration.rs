use crate::ast::handler::{HandlerDeclaration, HandlerGroupDeclaration};
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_type_expr::jump_to_definition_in_type_expr_kind;
use crate::search::search_availability::search_availability;

pub(super) fn jump_to_definition_in_handler_declaration(schema: &Schema, source: &Source, handler_declaration: &HandlerDeclaration, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = handler_declaration.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    namespace_path.pop();
    let availability = search_availability(schema, source, &namespace_path);
    if handler_declaration.input_type().span().contains_line_col(line_col) {
        return jump_to_definition_in_type_expr_kind(
            schema,
            source,
            &handler_declaration.input_type.kind,
            &namespace_path,
            line_col,
            &vec![],
            availability
        );
    }
    if handler_declaration.output_type.span().contains_line_col(line_col) {
        return jump_to_definition_in_type_expr_kind(
            schema,
            source,
            &handler_declaration.output_type.kind,
            &namespace_path,
            line_col,
            &vec![],
            availability
        );
    }
    vec![]
}

pub(super) fn jump_to_definition_in_handler_group_declaration(schema: &Schema, source: &Source, handler_group_declaration: &HandlerGroupDeclaration, line_col: (usize, usize)) -> Vec<Definition> {
    for handler_declaration in handler_group_declaration.handler_declarations() {
        if handler_declaration.span.contains_line_col(line_col) {
            return jump_to_definition_in_handler_declaration(
                schema,
                source,
                handler_declaration,
                line_col,
            );
        }
    }
    vec![]
}
