use crate::ast::schema::Schema;
use crate::ast::top::Top;
use crate::completion::completion_context::CompletionContext;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_model::find_completion_in_model;
use crate::search::search_top::search_top;

pub fn find_completion(schema: &Schema, file_path: &str, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if let Some(source) = schema.source_at_path(file_path) {
        let mut context = CompletionContext::new(schema, source);
        if let Some(top) = search_top(schema, file_path, line_col) {
            match top {
                Top::Model(m) => {
                    return find_completion_in_model(schema, source, m, line_col);
                }
                _ => ()
            }
        }
    }
    vec![]
}