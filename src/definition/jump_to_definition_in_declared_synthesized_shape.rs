use std::sync::Arc;
use crate::ast::decorator::Decorator;
use crate::ast::node::Node;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::synthesized_shape_declaration::SynthesizedShapeDeclaration;
use crate::ast::synthesized_shape_field_declaration::SynthesizedShapeFieldDeclaration;
use crate::availability::Availability;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list::jump_to_definition_in_argument_list;
use crate::definition::jump_to_definition_in_field::jump_to_definition_in_field;
use crate::search::search_availability::search_availability;
use crate::search::search_identifier_path::search_identifier_path_names_with_filter_to_path;
use crate::traits::node_trait::NodeTrait;
use crate::utils::top_filter::top_filter_for_any_model_field_decorators;

pub(super) fn jump_to_definition_in_declared_synthesized_shape<'a>(
    schema: &'a Schema,
    source: &'a Source,
    synthesized_shape_declaration: &'a SynthesizedShapeDeclaration,
    line_col: (usize, usize),
) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = synthesized_shape_declaration.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = search_availability(schema, source, &namespace_path);

    for dynamic_field in synthesized_shape_declaration.dynamic_fields() {
        if dynamic_field.span().contains_line_col(line_col) {
            return jump_to_definition_in_declared_synthesized_shape_dynamic_field(
                schema,
                source,
                dynamic_field,
                &namespace_path,
                line_col,
                &top_filter_for_any_model_field_decorators(),
                availability,
            );
        }
    }
    for field in synthesized_shape_declaration.static_fields() {
        if field.span.contains_line_col(line_col) {
            return jump_to_definition_in_field(schema, source, field, line_col, &vec![], availability);
        }
    }
    vec![]
}

pub(super) fn jump_to_definition_in_declared_synthesized_shape_dynamic_field<'a>(
    schema: &'a Schema,
    source: &'a Source,
    synthesized_shape_field_declaration: &'a SynthesizedShapeFieldDeclaration,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Vec<Definition> {
    let mut user_typed_spaces = vec![];
    let mut selector_span = None;
    for identifier in synthesized_shape_field_declaration.decorator_identifier_path().identifiers() {
        if identifier.span.contains_line_col(line_col) {
            user_typed_spaces.push(identifier.name());
            selector_span = Some(identifier.span);
            break
        } else {
            user_typed_spaces.push(identifier.name());
        }
    }
    if let Some(selector_span) = selector_span {
        // find in decorator path body
        let reference = search_identifier_path_names_with_filter_to_path(&user_typed_spaces, schema, source, namespace_path, filter, availability);
        match reference {
            Some(path) => {
                let top = schema.find_top_by_path(&path).unwrap();
                vec![Definition {
                    path: schema.source(*path.get(0).unwrap()).unwrap().file_path.clone(),
                    selection_span: selector_span,
                    target_span: top.span(),
                    identifier_span: match top {
                        Node::DecoratorDeclaration(d) => d.identifier().span,
                        Node::Namespace(n) => n.span,
                        _ => unreachable!()
                    }
                }]
            },
            None => vec![],
        }
    } else {
        vec![]
    }
}