use crate::availability::Availability;
use crate::ast::literals::TupleLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;

pub(super) fn find_completion_in_tuple_literal(schema: &Schema, source: &Source, tuple_literal: &TupleLiteral, line_col: (usize, usize), namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    for expression in &tuple_literal.expressions {
        if expression.span().contains_line_col(line_col) {
            return find_completion_in_expression(schema, source, expression, line_col, namespace_path, availability);
        }
    }
    vec![]
}
