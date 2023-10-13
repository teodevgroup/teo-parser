use serde::Serialize;
use crate::ast::span::Span;

#[derive(Debug, Serialize)]
pub struct Definition {
    pub(crate) path: String,
    pub(crate) selection_span: Span,
    pub(crate) target_span: Span,
    pub(crate) identifier_span: Span,
}

