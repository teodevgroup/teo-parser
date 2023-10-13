use crate::ast::literals::EnumVariantLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::definition::definition::Definition;

pub(super) fn jump_to_definition_in_enum_variant_literal<'a>(
    schema: &'a Schema,
    source: &'a Source,
    enum_variant_literal: &'a EnumVariantLiteral,
    namespace_path: &Vec<&'a str>,
    line_col: (usize, usize),
) -> Vec<Definition> {
    vec![]
}