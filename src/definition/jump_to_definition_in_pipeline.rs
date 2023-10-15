use crate::ast::pipeline::Pipeline;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::definition::definition::Definition;
use crate::r#type::r#type::Type;
use crate::search::search_pipeline_unit::search_pipeline_unit;

pub(super) fn jump_to_definition_in_pipeline<'a>(
    schema: &'a Schema,
    source: &'a Source,
    pipeline: &'a Pipeline,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
) -> Vec<Definition> {
    if pipeline.unit.span.contains_line_col(line_col) {
        jump_to_definition_in_pipeline_unit(
            schema,
            source,
            pipeline.unit.as_ref(),
            namespace_path,
            line_col,
            expect,
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
    expect: &Type,
) -> Vec<Definition> {
    search_pipeline_unit(
        schema,
        source,
        unit,
        namespace_path,
        line_col,
        |argument_list, path| {
            vec![]
        },
        |path| {
            vec![]
        },
        vec![]
    )
}