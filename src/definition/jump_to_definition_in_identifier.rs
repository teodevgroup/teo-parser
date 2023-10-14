use crate::ast::identifier::Identifier;
use crate::ast::reference::ReferenceType;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::top::Top;
use crate::definition::definition::Definition;
use crate::search::search_identifier_path::search_identifier_path_in_source;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn jump_to_definition_in_identifier<'a>(
    schema: &'a Schema,
    source: &'a Source,
    identifier: &'a Identifier,
    namespace_path: &Vec<&'a str>,
    _line_col: (usize, usize),
) -> Vec<Definition> {
    if let Some(reference) = search_identifier_path_in_source(
        schema,
        source,
        namespace_path,
        &vec![identifier.name()],
        &top_filter_for_reference_type(ReferenceType::Default)
    ) {
        match schema.find_top_by_path(&reference).unwrap() {
            Top::Constant(c) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: c.identifier.span,
                target_span: c.span,
                identifier_span: identifier.span,
            }],
            Top::Namespace(n) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: n.identifier.span,
                target_span: n.span,
                identifier_span: identifier.span,
            }],
            Top::Model(m) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: m.identifier.span,
                target_span: m.span,
                identifier_span: identifier.span,
            }],
            Top::Enum(e) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: e.identifier.span,
                target_span: e.span,
                identifier_span: identifier.span,
            }],
            Top::StructDeclaration(s) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: s.identifier.span,
                target_span: s.span,
                identifier_span: identifier.span,
            }],
            Top::Interface(i) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: i.identifier.span,
                target_span: i.span,
                identifier_span: identifier.span,
            }],
            Top::Config(c) => vec![Definition {
                path: schema.source(*reference.get(0).unwrap()).unwrap().file_path.clone(),
                selection_span: c.identifier.as_ref().map_or(c.keyword.span, |i| i.span),
                target_span: c.span,
                identifier_span: identifier.span,
            }],
            _ => unreachable!()
        }
    } else {
        vec![]
    }
}