use serde::Serialize;
use crate::ast::schema::Schema;
use crate::completion::completion_context::CompletionContext;
use crate::definition::definition_context::DefinitionContext;

#[derive(Debug, Serialize)]
pub struct CompletionItem {
    pub(crate) label: String,
    pub(crate) label_detail: Option<String>,
    pub(crate) documentation: Option<String>,
    pub(crate) detail: Option<String>,
}

pub fn find_auto_complete_items(schema: &Schema, file_path: &str, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if let Some(source) = schema.sources().iter().find(|s| s.file_path.as_str() == file_path) {
        let mut context = CompletionContext::new(schema, source);
        return source.find_auto_complete_items(&mut context, line_col);
    }
    vec![]
}