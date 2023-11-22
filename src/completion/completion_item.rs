use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct CompletionItem {
    pub label: String,
    pub namespace_path: Option<String>,
    pub documentation: Option<String>,
    pub detail: Option<String>,
}