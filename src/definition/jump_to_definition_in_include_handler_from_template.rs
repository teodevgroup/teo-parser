use crate::ast::handler::HandlerDeclaration;
use crate::ast::include_handler_from_template::IncludeHandlerFromTemplate;
use crate::ast::node::Node;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::search::search_availability::search_availability;
use crate::search::search_identifier_path::search_identifier_path_names_with_filter_to_path;
use crate::traits::node_trait::NodeTrait;
use crate::utils::top_filter::top_filter_for_handler_template;

pub(super) fn jump_to_definition_in_include_handler_from_template(schema: &Schema, source: &Source, include_handler_from_template: &IncludeHandlerFromTemplate, line_col: (usize, usize)) -> Vec<Definition> {
    let mut namespace_path: Vec<_> = include_handler_from_template.string_path.iter().map(|s| s.as_str()).collect();
    namespace_path.pop();
    let availability = search_availability(schema, source, &namespace_path);
    let identifier_path = include_handler_from_template.identifier_path();
    if identifier_path.span().contains_line_col(line_col) {
        let mut user_typed_spaces = vec![];
        let mut selector_span = None;
        for identifier in identifier_path.identifiers() {
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
            let reference = search_identifier_path_names_with_filter_to_path(&user_typed_spaces, schema, source, &namespace_path, &top_filter_for_handler_template(), availability);
            match reference {
                Some(path) => {
                    let top = schema.find_top_by_path(&path).unwrap();
                    vec![Definition {
                        path: schema.source(*path.get(0).unwrap()).unwrap().file_path.clone(),
                        selection_span: selector_span,
                        target_span: top.span(),
                        identifier_span: match top {
                            Node::HandlerTemplateDeclaration(d) => d.identifier().span,
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
    } else {
        vec![]
    }
}