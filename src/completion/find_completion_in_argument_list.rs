use std::collections::BTreeSet;
use maplit::btreeset;
use crate::ast::argument::Argument;
use crate::ast::argument_list::ArgumentList;
use crate::ast::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;

pub(super) fn find_completion_in_argument_list(schema: &Schema, source: &Source, argument_list: &ArgumentList, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability, names: Vec<Vec<&str>>) -> Vec<CompletionItem> {
    for argument in &argument_list.arguments {
        if argument.span.contains_line_col(line_col) {
            return find_completion_in_argument(schema, source, argument, line_col, namespace_path, availability, &names);
        }
    }
    vec![]
}

pub(super) fn find_completion_in_argument(schema: &Schema, source: &Source, argument: &Argument, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability, names: &Vec<Vec<&str>>) -> Vec<CompletionItem> {
    if let Some(identifier) = &argument.name {
        if identifier.span.contains_line_col(line_col) {
            return completion_items_from_names(names);
        }
    }
    if argument.value.span().contains_line_col(line_col) {
        return find_completion_in_expression(schema, source, &argument.value, line_col, namespace_path, availability);
    }
    vec![]
}

fn completion_items_from_names(names: &Vec<Vec<&str>>) -> Vec<CompletionItem> {
    let mut result: BTreeSet<&str> = btreeset!{};
    for names in names {
        for name in names {
            result.push(*name);
        }
    }
    result.iter().map(|name| CompletionItem {
        label: name.to_string(),
        namespace_path: None,
        documentation: None,
        detail: None,
    }).collect()
}