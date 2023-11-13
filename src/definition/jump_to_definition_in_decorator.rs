use std::sync::Arc;
use crate::availability::Availability;
use crate::ast::decorator::Decorator;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list::jump_to_definition_in_argument_list;
use crate::search::search_identifier_path::{search_identifier_path_names_with_filter_to_path, search_identifier_path_names_with_filter_to_type_and_value};

pub(super) fn jump_to_definition_in_decorator<'a>(
    schema: &'a Schema,
    source: &'a Source,
    decorator: &'a Decorator,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Vec<Definition> {
    let mut user_typed_spaces = vec![];
    let mut selector_span = None;
    for identifier in decorator.identifier_path.identifiers.iter() {
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
                        Top::DecoratorDeclaration(d) => d.identifier.span,
                        Top::Namespace(n) => n.span,
                        _ => unreachable!()
                    }
                }]
            },
            None => vec![],
        }
    } else {
        let reference = search_identifier_path_names_with_filter_to_path(&user_typed_spaces, schema, source, namespace_path, filter, availability);
        // found in argument lists
        if let Some(argument_list) = &decorator.argument_list {
            if let Some(reference) = reference {
                jump_to_definition_in_argument_list(
                    schema,
                    source,
                    argument_list,
                    namespace_path,
                    Some(reference.clone()),
                    line_col,
                    availability,
                )
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    }
}