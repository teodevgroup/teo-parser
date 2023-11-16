use crate::availability::Availability;
use crate::ast::identifier::Identifier;
use crate::ast::node::Node;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::search::search_identifier_path::{search_identifier_path_names_with_filter_to_path, search_identifier_path_names_with_filter_to_type_and_value};
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn jump_to_definition_in_identifier<'a>(
    schema: &'a Schema,
    source: &'a Source,
    identifier: &'a Identifier,
    namespace_path: &Vec<&'a str>,
    _line_col: (usize, usize),
    availability: Availability,
) -> Vec<Definition> {
    if let Some(reference) = search_identifier_path_names_with_filter_to_path(
        &vec![identifier.name()],
        schema,
        source,
        namespace_path,
        &top_filter_for_reference_type(ReferenceSpace::Default),
        availability,
    ) {
        match schema.find_top_by_path(&reference).unwrap() {
            Node::Constant(c) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: identifier.span,
                target_span: c.span,
                identifier_span: c.identifier().span,
            }],
            Node::Namespace(n) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: identifier.span,
                target_span: n.span,
                identifier_span: n.identifier().span,
            }],
            Node::Model(m) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: identifier.span,
                target_span: m.span,
                identifier_span: m.identifier().span,
            }],
            Node::Enum(e) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: identifier.span,
                target_span: e.span,
                identifier_span: e.identifier().span,
            }],
            Node::StructDeclaration(s) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: identifier.span,
                target_span: s.span,
                identifier_span: s.identifier().span,
            }],
            Node::InterfaceDeclaration(i) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: identifier.span,
                target_span: i.span,
                identifier_span: i.identifier().span,
            }],
            Node::Config(c) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: identifier.span,
                target_span: c.span,
                identifier_span: c.identifier().map_or(c.keyword().span, |i| i.span),
            }],
            _ => unreachable!()
        }
    } else {
        vec![]
    }
}