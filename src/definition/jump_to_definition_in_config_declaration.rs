use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_field::jump_to_definition_in_field;
use crate::search::search_availability::search_availability;

pub(super) fn jump_to_definition_in_config_declaration(schema: &Schema, source: &Source, config_declaration: &ConfigDeclaration, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = config_declaration.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = search_availability(schema, source, &namespace_path);
    for field in config_declaration.fields() {
        if field.span.contains_line_col(line_col) {
            return jump_to_definition_in_field(
                schema,
                source,
                field,
                line_col,
                &vec![],
                availability,
            );
        }
    }
    vec![]
}