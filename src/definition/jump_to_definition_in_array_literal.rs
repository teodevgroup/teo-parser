use crate::availability::Availability;
use crate::ast::literals::ArrayLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::definition::jump_to_definition_in_expression::jump_to_definition_in_expression;
use crate::r#type::r#type::Type;

pub(super) fn jump_to_definition_in_array_literal<'a>(
    schema: &'a Schema,
    source: &'a Source,
    array_literal: &'a ArrayLiteral,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
    availability: Availability,
) -> Vec<Definition> {
    for expression in &array_literal.expressions {
        if expression.span().contains_line_col(line_col) {
            return jump_to_definition_in_expression(
                schema,
                source,
                expression,
                namespace_path,
                line_col,
                expression.resolved().r#type(),
                availability,
            );
        }
    }
    vec![]
}