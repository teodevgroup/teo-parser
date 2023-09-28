use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct GenericsDeclaration {
    span: Span,
    items: Vec<GenericsDeclarationItem>,
}

#[derive(Debug)]
pub struct GenericsDeclarationItem {
    span: Span,
    identifier: Identifier,
}
