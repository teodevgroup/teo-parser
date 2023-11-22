use std::sync::Arc;
use crate::ast::node::Node;
use crate::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::collect_reference_completion::collect_reference_completion_in_source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::completion_item_from_top::completion_item_from_top;

pub fn find_top_completion_with_filter<'a>(
    schema: &'a Schema,
    source: &'a Source,
    namespace_path: &Vec<&str>,
    user_typed_prefix: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Vec<CompletionItem> {
    let paths = collect_reference_completion_in_source(schema, source, namespace_path, user_typed_prefix, filter, availability);
    paths.iter().filter_map(|path| {
        let top = schema.find_top_by_path(path).unwrap();
        if user_typed_prefix.is_empty() {
            Some(completion_item_from_top(top))
        } else {
            let user_typed = user_typed_prefix.join(".");
            let actual = top.str_path().unwrap().join(".");
            if actual.starts_with(&user_typed) {
                Some(completion_item_from_top(top))
            } else {
                None
            }
        }
    }).collect()
}