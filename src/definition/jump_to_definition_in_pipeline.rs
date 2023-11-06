use crate::ast::availability::Availability;
use crate::ast::pipeline::Pipeline;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::top::Top;
use crate::ast::unit::Unit;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_argument_list::jump_to_definition_in_argument_list;
use crate::search::search_pipeline_unit_for_definition::search_pipeline_unit_for_definition;

pub(super) fn jump_to_definition_in_pipeline<'a>(
    schema: &'a Schema,
    source: &'a Source,
    pipeline: &'a Pipeline,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    availability: Availability,
) -> Vec<Definition> {
    if pipeline.unit.span.contains_line_col(line_col) {
        jump_to_definition_in_pipeline_unit(
            schema,
            source,
            pipeline.unit.as_ref(),
            namespace_path,
            line_col,
            availability
        )
    } else {
        vec![]
    }
}

pub(super) fn jump_to_definition_in_pipeline_unit<'a>(
    schema: &'a Schema,
    source: &'a Source,
    unit: &'a Unit,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    availability: Availability,
) -> Vec<Definition> {
    search_pipeline_unit_for_definition(
        schema,
        source,
        unit,
        namespace_path,
        line_col,
        |argument_list, path| {
            jump_to_definition_in_argument_list(
                schema,
                source,
                argument_list,
                namespace_path,
                path.clone(),
                line_col,
                availability
            )
        },
        |span ,path| {
            let top = schema.find_top_by_path(path).unwrap();
            match top {
                Top::Namespace(namespace) => vec![Definition {
                    path: schema.source(namespace.source_id()).unwrap().file_path.clone(),
                    selection_span: span,
                    target_span: namespace.span,
                    identifier_span: namespace.identifier.span,
                }],
                Top::PipelineItemDeclaration(pipeline_item_declaration) => vec![Definition {
                    path: schema.source(pipeline_item_declaration.source_id()).unwrap().file_path.clone(),
                    selection_span: span,
                    target_span: pipeline_item_declaration.span,
                    identifier_span: pipeline_item_declaration.identifier.span,
                }],
                _ => unreachable!(),
            }
        },
        vec![],
        availability
    )
}