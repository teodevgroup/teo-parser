use crate::ast::literals::EnumVariantLiteral;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::r#type::Type;

pub(super) fn find_completion_in_enum_variant_literal(schema: &Schema, source: &Source, enum_variant_literal: &EnumVariantLiteral, line_col: (usize, usize), namespace_path: &Vec<&str>, expect: &Type) -> Vec<CompletionItem> {
    vec![]
}
