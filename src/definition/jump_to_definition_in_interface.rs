use crate::ast::interface::InterfaceDeclaration;
use crate::ast::model::Model;
use crate::ast::reference::ReferenceType;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_decorator::jump_to_definition_in_decorator;
use crate::definition::jump_to_definition_in_field::jump_to_definition_in_field;
use crate::search::search_availability::search_availability;
use crate::utils::top_filter::{top_filter_for_any_model_field_decorators, top_filter_for_reference_type};

pub(super) fn jump_to_definition_in_interface(schema: &Schema, source: &Source, interface: &InterfaceDeclaration, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = interface.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = search_availability(schema, source, &namespace_path);

    let mut generics_declarations = vec![];
    if let Some(generics_declaration) = &interface.generics_declaration {
        generics_declarations.push(generics_declaration);
    }
    for field in &interface.fields {
        if field.span.contains_line_col(line_col) {
            return jump_to_definition_in_field(schema, source, field, line_col, &generics_declarations, availability);
        }
    }
    vec![]
}