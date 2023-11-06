use crate::ast::availability::Availability;
use crate::ast::literals::{DictionaryLiteral};
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;

pub(super) fn find_completion_in_dictionary_literal(schema: &Schema, source: &Source, dictionary_literal: &DictionaryLiteral, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    for (key_expression, value_expression) in &dictionary_literal.expressions {
        if key_expression.span().contains_line_col(line_col) {
            return find_completion_in_expression(schema, source, key_expression, line_col, namespace_path, availability);
        }
        if value_expression.span().contains_line_col(line_col) {
            return find_completion_in_expression(schema, source, value_expression, line_col, namespace_path, availability);
        }
    }
    vec![]
}
