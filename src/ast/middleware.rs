use crate::ast::identifier::ASTIdentifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct MiddlewareDeclaration {
    pub(crate) id: usize,
    pub(crate) source_id: usize,
    pub(crate) identifier: ASTIdentifier,
    pub(crate) span: Span,
}