use crate::ast::literals::EnumVariantLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::r#type::Type;

pub(super) fn find_completion_in_enum_variant_literal(_schema: &Schema, _source: &Source, _enum_variant_literal: &EnumVariantLiteral, _line_col: (usize, usize), _namespace_path: &Vec<&str>, _expect: &Type) -> Vec<CompletionItem> {
    vec![]
}
