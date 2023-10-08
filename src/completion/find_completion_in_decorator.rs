use crate::ast::decorator::Decorator;
use crate::ast::reference::ReferenceType;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::collect_reference_completion::collect_reference_completion_in_source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::completion_item_from_top::completion_item_from_top;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn find_completion_in_decorator<'a>(
    schema: &'a Schema,
    source: &'a Source,
    decorator: &'a Decorator,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    reference_type: ReferenceType
) -> Vec<CompletionItem> {
    let mut user_typed_spaces = vec![];
    for identifier in decorator.identifier_path.identifiers.iter() {
        if identifier.span.contains_line_col(line_col) {
            break
        } else {
            user_typed_spaces.push(identifier.name());
        }
    }
    let mut combined_namespace_path = namespace_path.clone();
    combined_namespace_path.extend(user_typed_spaces);
    find_completion_in_empty_decorator(schema, source, &combined_namespace_path, reference_type)
}

pub(super) fn find_completion_in_empty_decorator<'a>(
    schema: &'a Schema,
    source: &'a Source,
    namespace_path: &Vec<&'a str>,
    reference_type: ReferenceType
) -> Vec<CompletionItem> {
    let paths = collect_reference_completion_in_source(schema, source, namespace_path, &top_filter_for_reference_type(reference_type));
    paths.iter().map(|path| {
        let top = schema.find_top_by_path(path).unwrap();
        completion_item_from_top(top)
    }).collect()
}