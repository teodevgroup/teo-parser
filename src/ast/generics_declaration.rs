use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct GenericsDeclaration {
    pub(crate) span: Span,
    pub(crate) items: Vec<Identifier>,
}
