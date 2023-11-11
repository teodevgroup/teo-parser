use std::sync::Arc;
use crate::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::top::Top;
use crate::completion::collect_reference_completion::collect_reference_completion_in_source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::completion_item_from_top::completion_item_from_top;

pub fn find_top_completion_with_filter<'a>(
    schema: &'a Schema,
    source: &'a Source,
    namespace_path: &Vec<&str>,
    user_typed_prefix: &Vec<&str>,
    filter: &Arc<dyn Fn(&Top) -> bool>,
    availability: Availability,
) -> Vec<CompletionItem> {
    let paths = collect_reference_completion_in_source(schema, source, namespace_path, user_typed_prefix, filter, availability);
    paths.iter().map(|path| {
        let top = schema.find_top_by_path(path).unwrap();
        completion_item_from_top(top)
    }).collect()
}