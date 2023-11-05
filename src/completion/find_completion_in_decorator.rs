use std::sync::Arc;
use crate::ast::decorator::Decorator;
use crate::ast::reference::ReferenceType;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::top::Top;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_argument_list::find_completion_in_argument_list;
use crate::completion::find_top_completion_with_filter::find_top_completion_with_filter;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn find_completion_in_decorator<'a>(
    schema: &'a Schema,
    source: &'a Source,
    decorator: &'a Decorator,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    reference_type: ReferenceType
) -> Vec<CompletionItem> {
    find_completion_in_decorator_with_filter(schema, source, decorator, namespace_path, line_col, &top_filter_for_reference_type(reference_type))
}

pub(super) fn find_completion_in_decorator_with_filter<'a>(
    schema: &'a Schema,
    source: &'a Source,
    decorator: &'a Decorator,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    filter: &Arc<dyn Fn(&Top) -> bool>,
) -> Vec<CompletionItem> {
    if let Some(argument_list) = &decorator.argument_list {
        if argument_list.span.contains_line_col(line_col) {
            return find_completion_in_argument_list(schema, source, argument_list, line_col, namespace_path);
        }
    }
    let mut user_typed_spaces = vec![];
    for identifier in decorator.identifier_path.identifiers.iter() {
        if identifier.span.contains_line_col(line_col) {
            break
        } else {
            user_typed_spaces.push(identifier.name());
        }
    }
    find_top_completion_with_filter(schema, source, namespace_path, &user_typed_spaces, filter)
}

pub(super) fn find_completion_in_empty_decorator<'a>(
    schema: &'a Schema,
    source: &'a Source,
    namespace_path: &Vec<&'a str>,
    reference_type: ReferenceType
) -> Vec<CompletionItem> {
    find_top_completion_with_filter(schema, source, namespace_path, &vec![], &top_filter_for_reference_type(reference_type))
}
