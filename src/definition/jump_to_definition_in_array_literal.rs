use crate::ast::literals::ArrayLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;

pub(super) fn jump_to_definition_in_array_literal<'a>(
    schema: &'a Schema,
    source: &'a Source,
    array_literal: &'a ArrayLiteral,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
) -> Vec<Definition> {
    vec![]
}