use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CompletionItem {
    pub(crate) label: String,
    pub(crate) namespace_path: Option<String>,
    pub(crate) documentation: Option<String>,
    pub(crate) detail: Option<String>,
}