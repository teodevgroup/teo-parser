use crate::ast::argument_list::ArgumentList;
use crate::ast::availability::Availability;
use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::search::search_identifier_path::search_identifier_path_in_source;
use crate::utils::top_filter::top_filter_for_pipeline;

pub fn search_pipeline_unit_for_auto_completion<HAL, HI, OUTPUT>(
    schema: &Schema,
    source: &Source,
    unit: &Unit,
    namespace_path: &Vec<&str>,
    line_col: (usize, usize),
    handle_argument_list: HAL,
    handle_identifier: HI,
    default: OUTPUT,
    availability: Availability,
) -> OUTPUT where
    HAL: Fn(&ArgumentList, Option<&PipelineItemDeclaration>) -> OUTPUT,
    HI: Fn(&Vec<&str>) -> OUTPUT,
{
    let mut user_typed_prefix: Vec<&str> = vec![];
    for expression in unit.expressions.iter() {
        if let Some(identifier) = expression.kind.as_identifier() {
            if identifier.span.contains_line_col(line_col) {
                return handle_identifier(&user_typed_prefix);
            } else {
                user_typed_prefix.push(identifier.name());
                if let Some(reference) = search_identifier_path_in_source(schema, source, namespace_path, &user_typed_prefix, &top_filter_for_pipeline(), availability) {
                    if schema.find_top_by_path(&reference).unwrap().is_pipeline_item_declaration() {
                        user_typed_prefix = vec![];
                    }
                } else {
                    user_typed_prefix = vec![];
                }
            }
        } else if let Some(argument_list) = expression.kind.as_argument_list() {
            if argument_list.span.contains_line_col(line_col) {
                return handle_argument_list(argument_list, search_identifier_path_in_source(schema, source, namespace_path, &user_typed_prefix, &top_filter_for_pipeline(), availability).map(|r| schema.find_top_by_path(&r).unwrap().as_pipeline_item_declaration()).flatten());
            } else {
                user_typed_prefix = vec![];
            }
        }
    }
    default
}