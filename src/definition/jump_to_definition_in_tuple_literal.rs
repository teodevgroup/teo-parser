use crate::ast::literals::TupleLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::r#type::r#type::Type;

pub(super) fn jump_to_definition_in_tuple_literal<'a>(
    schema: &'a Schema,
    source: &'a Source,
    tuple_literal: &'a TupleLiteral,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
) -> Vec<Definition> {
    vec![]
}