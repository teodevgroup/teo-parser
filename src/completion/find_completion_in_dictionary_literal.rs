use crate::ast::literals::{DictionaryLiteral};
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_dictionary_literal(schema: &Schema, source: &Source, dictionary_literal: &DictionaryLiteral, line_col: (usize, usize), namespace_path: &Vec<&str>) -> Vec<CompletionItem> {
    vec![]
}
