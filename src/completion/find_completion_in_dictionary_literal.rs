use crate::availability::Availability;
use crate::ast::literals::{DictionaryLiteral};
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;
use crate::r#type::Type;
use crate::traits::node_trait::NodeTrait;

pub(super) fn find_completion_in_dictionary_literal(schema: &Schema, source: &Source, dictionary_literal: &DictionaryLiteral, line_col: (usize, usize), namespace_path: &Vec<&str>, expect: &Type, availability: Availability) -> Vec<CompletionItem> {
    for named_expression in dictionary_literal.expressions() {
        let key_expression = named_expression.key();
        let value_expression = named_expression.value();
        if key_expression.span().contains_line_col(line_col) && key_expression.kind.as_bracket_expression().is_some() {
            return find_completion_in_expression(schema, source, key_expression, line_col, namespace_path, &Type::String, availability);
        }
        if value_expression.span().contains_line_col(line_col) {
            return find_completion_in_expression(schema, source, value_expression, line_col, namespace_path, expect.as_dictionary().unwrap_or(&Type::Undetermined), availability);
        }
    }
    vec![]
}
