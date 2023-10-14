use crate::ast::literals::DictionaryLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;
use crate::r#type::r#type::Type;

pub(super) fn jump_to_definition_in_dictionary_literal<'a>(
    schema: &'a Schema,
    source: &'a Source,
    dictionary_literal: &'a DictionaryLiteral,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
    expect: &Type,
) -> Vec<Definition> {
    vec![]
}