use serde::Serialize;
use crate::ast::schema::Schema;
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::search::search_top::search_top;

#[derive(Debug, Serialize)]
pub struct Definition {
    pub(crate) path: String,
    pub(crate) selection_span: Span,
    pub(crate) target_span: Span,
    pub(crate) identifier_span: Span,
}

