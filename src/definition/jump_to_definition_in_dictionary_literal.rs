use crate::availability::Availability;
use crate::ast::literals::DictionaryLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_expression::jump_to_definition_in_expression;
use crate::r#type::r#type::Type;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn jump_to_definition_in_dictionary_literal<'a>(
    schema: &'a Schema,
    source: &'a Source,
    dictionary_literal: &'a DictionaryLiteral,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
    availability: Availability,
) -> Vec<Definition> {
    for (key_expression, value_expression) in dictionary_literal.expressions() {
        if key_expression.span().contains_line_col(line_col) {
            return jump_to_definition_in_expression(
                schema,
                source,
                key_expression,
                namespace_path,
                line_col,
                key_expression.resolved().r#type(),
                availability
            );
        }
        if value_expression.span().contains_line_col(line_col) {
            return jump_to_definition_in_expression(
                schema,
                source,
                value_expression,
                namespace_path,
                line_col,
                value_expression.resolved().r#type(),
                availability,
            );
        }
    }
    vec![]
}