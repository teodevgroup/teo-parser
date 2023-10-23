use crate::ast::argument_list::ArgumentList;
use crate::ast::availability::Availability;
use crate::ast::namespace::Namespace;
use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::ast::unit::Unit;
use crate::search::search_identifier_path::search_identifier_path_in_source;
use crate::utils::top_filter::top_filter_for_pipeline;

pub fn search_pipeline_unit<HAL, HI, OUTPUT>(
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
    HAL: Fn(&ArgumentList, &Vec<usize>) -> OUTPUT,
    HI: Fn(Span, &Vec<usize>) -> OUTPUT,
{
    let mut current_namespace: Option<&Namespace> = None;
    let mut current_pipeline_item: Option<&PipelineItemDeclaration> = None;
    for (index, expression) in unit.expressions.iter().enumerate() {
        if let Some(identifier) = expression.kind.as_identifier() {
            if let Some(this_top) = if current_namespace.is_some() {
                current_namespace.unwrap().find_top_by_name(identifier.name(), &top_filter_for_pipeline(), availability)
            } else if let Some(path) = search_identifier_path_in_source(
                schema,
                source,
                namespace_path,
                &vec![identifier.name()],
                &top_filter_for_pipeline(),
                availability,
            ) {
                schema.find_top_by_path(&path)
            } else {
                None
            } {
                match this_top {
                    Top::Namespace(namespace) => current_namespace = Some(namespace),
                    Top::PipelineItemDeclaration(pipeline_item_declaration) => current_pipeline_item = Some(pipeline_item_declaration),
                    _ => unreachable!(),
                }
                if identifier.span.contains_line_col(line_col) {
                    return handle_identifier(identifier.span, this_top.path());
                }
            } else {
                current_pipeline_item = None;
                current_namespace = None;
                if identifier.span.contains_line_col(line_col) {
                    return default;
                }
            }
        } else if let Some(argument_list) = expression.kind.as_argument_list() {
            if argument_list.span.contains_line_col(line_col) {
                if let Some(current_pipeline_item) = current_pipeline_item {
                    return handle_argument_list(argument_list, &current_pipeline_item.path);
                }
            } else {
                current_pipeline_item = None;
                current_namespace = None;
            }
        }
    }
    default
}