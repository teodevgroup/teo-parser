use std::collections::BTreeSet;
use maplit::btreeset;
use crate::ast::argument::Argument;
use crate::ast::argument_list::ArgumentList;
use crate::ast::partial_argument::PartialArgument;
use crate::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::{find_completion_in_empty_expression, find_completion_in_expression};
use crate::r#type::Type;
use crate::traits::node_trait::NodeTrait;

pub(super) fn find_completion_in_argument_list(schema: &Schema, source: &Source, argument_list: &ArgumentList, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability, names: Vec<Vec<&str>>) -> Vec<CompletionItem> {
    for partial_argument in argument_list.partial_arguments() {
        if partial_argument.span.contains_line_col(line_col) {
            return find_completion_in_partial_argument(schema, source, partial_argument, line_col, namespace_path, availability);
        }
    }
    for argument in argument_list.arguments() {
        if argument.span.contains_line_col(line_col) {
            return find_completion_in_argument(schema, source, argument, line_col, namespace_path, availability, &names);
        }
    }
    vec![]
}

pub(super) fn find_completion_in_partial_argument(schema: &Schema, source: &Source, partial_argument: &PartialArgument, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    if partial_argument.colon().span.contains_line_col(line_col) {
        find_completion_in_empty_expression(schema, source, namespace_path, availability)
    } else {
        vec![]
    }
}

pub(super) fn find_completion_in_argument(schema: &Schema, source: &Source, argument: &Argument, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability, names: &Vec<Vec<&str>>) -> Vec<CompletionItem> {
    let undetermined = Type::Undetermined;
    if let Some(identifier) = argument.name() {
        if identifier.span.contains_line_col(line_col) {
            return completion_items_from_names(names);
        }
        if argument.value().span().contains_line_col(line_col) {
            return find_completion_in_expression(schema, source, argument.value(), line_col, namespace_path, if argument.is_resolved() { &argument.resolved().expect } else { &undetermined }, availability);
        }
    } else {
        let mut results = find_completion_in_expression(schema, source, argument.value(), line_col, namespace_path, if argument.is_resolved() { &argument.resolved().expect } else { &undetermined }, availability);
        if argument.value().is_single_identifier() {
            results.extend(completion_items_from_names(names));
        }
        return results;
    }
    vec![]
}

fn completion_items_from_names(names: &Vec<Vec<&str>>) -> Vec<CompletionItem> {
    let mut result: BTreeSet<&str> = btreeset!{};
    for names in names {
        for name in names {
            result.insert(*name);
        }
    }
    result.iter().map(|name| CompletionItem {
        label: name.to_string(),
        namespace_path: None,
        documentation: None,
        detail: None,
    }).collect()
}