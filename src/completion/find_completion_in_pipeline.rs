use crate::ast::availability::Availability;
use crate::ast::pipeline::Pipeline;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::completion::collect_argument_list_names::collect_argument_list_names_from_pipeline_item_declaration;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_argument_list::find_completion_in_argument_list;
use crate::completion::find_top_completion_with_filter::find_top_completion_with_filter;
use crate::search::search_pipeline_unit_for_auto_completion::search_pipeline_unit_for_auto_completion;
use crate::utils::top_filter::top_filter_for_pipeline;

pub(super) fn find_completion_in_pipeline(schema: &Schema, source: &Source, pipeline: &Pipeline, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    find_completion_in_pipeline_unit(schema, source, pipeline.unit.as_ref(), line_col, namespace_path, availability)
}

fn find_completion_in_pipeline_unit(schema: &Schema, source: &Source, unit: &Unit, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    search_pipeline_unit_for_auto_completion(
        schema,
        source,
        unit,
        namespace_path,
        line_col,
        |argument_list, path| {
            let names = if let Some(path) = path {
                collect_argument_list_names_from_pipeline_item_declaration(path)
            } else {
                vec![]
            };
            find_completion_in_argument_list(schema, source, argument_list, line_col, namespace_path, availability, names)
        },
        |user_typed_prefix| {
            find_top_completion_with_filter(schema, source, namespace_path, user_typed_prefix, &top_filter_for_pipeline(), availability)
        },
        vec![],
        availability
    )
}