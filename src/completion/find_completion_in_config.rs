use crate::ast::config::Config;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;

pub(super) fn find_completion_in_config(schema: &Schema, source: &Source, config: &Config, line_col: (usize, usize)) -> Vec<CompletionItem> {
    vec![]
}