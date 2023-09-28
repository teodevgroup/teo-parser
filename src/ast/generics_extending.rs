use crate::ast::identifier_path::IdentifierPath;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct InterfaceExtending {
    pub(crate) span: Span,
    pub(crate) identifier_path: IdentifierPath,
    pub(crate) items: Vec<InterfaceExtending>,
}
