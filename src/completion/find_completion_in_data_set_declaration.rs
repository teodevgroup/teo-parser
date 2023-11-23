use crate::ast::data_set::{DataSet, DataSetGroup, DataSetRecord};
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;
use crate::completion::find_top_completion_with_filter::find_top_completion_with_filter;
use crate::r#type::Type;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::top_filter_for_model;

pub(super) fn find_completion_in_data_set_declaration(schema: &Schema, source: &Source, data_set: &DataSet, line_col: (usize, usize)) -> Vec<CompletionItem> {
    for group in data_set.groups() {
        if group.span.contains_line_col(line_col) {
            return find_completion_in_data_set_group(schema, source, group, line_col);
        }
    }
    vec![]
}

pub(super) fn find_completion_in_data_set_group(schema: &Schema, source: &Source, group: &DataSetGroup, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if group.identifier_path().span.contains_line_col(line_col) {
        let mut user_typed_spaces = vec![];
        for identifier in group.identifier_path().identifiers() {
            if identifier.span.contains_line_col(line_col) {
                break
            } else {
                user_typed_spaces.push(identifier.name());
            }
        }
        return find_top_completion_with_filter(schema, source, &group.namespace_str_path(), &user_typed_spaces, &top_filter_for_model(), group.availability());
    }
    for record in group.records() {
        if record.span.contains_line_col(line_col) {
            return find_completion_in_data_set_record(schema, source, record, line_col);
        }
    }
    vec![]
}

pub(super) fn find_completion_in_data_set_record(schema: &Schema, source: &Source, record: &DataSetRecord, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if record.dictionary().span.contains_line_col(line_col) {
        for expression in record.dictionary().expressions() {
            if expression.key().span().contains_line_col(line_col) {
                return vec![];
            } else if expression.value().span().contains_line_col(line_col) {
                let undetermined = Type::Undetermined;
                return find_completion_in_expression(schema, source, expression.value(), line_col, &record.namespace_str_path(), if expression.value().is_resolved() { expression.value().resolved().r#type() } else { &undetermined }, record.availability());
            }
        }
    }
    vec![]
}

