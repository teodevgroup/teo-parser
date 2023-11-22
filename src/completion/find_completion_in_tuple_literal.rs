use crate::availability::Availability;
use crate::ast::literals::TupleLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_expression::find_completion_in_expression;
use crate::r#type::Type;
use crate::traits::node_trait::NodeTrait;

pub(super) fn find_completion_in_tuple_literal(schema: &Schema, source: &Source, tuple_literal: &TupleLiteral, line_col: (usize, usize), namespace_path: &Vec<&str>, expect: &Type, availability: Availability) -> Vec<CompletionItem> {
    let types = expect.as_tuple();
    let undetermined = Type::Undetermined;
    for (index, expression) in tuple_literal.expressions().enumerate() {
        if expression.span().contains_line_col(line_col) {
            return find_completion_in_expression(schema, source, expression, line_col, namespace_path, types.map(|t| t.get(index)).flatten().unwrap_or(&undetermined),  availability);
        }
    }
    vec![]
}
