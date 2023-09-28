use crate::ast::identifier_path::IdentifierPath;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct GenericsExtending {
    span: Span,
    identifier_path: IdentifierPath,
    items: Vec<GenericsExtending>,
}
