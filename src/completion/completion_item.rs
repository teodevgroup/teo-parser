use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CompletionItem {
    pub(crate) label: String,
    pub(crate) label_detail: Option<String>,
    pub(crate) documentation: Option<String>,
    pub(crate) detail: Option<String>,
}