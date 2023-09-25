use crate::ast::expression::Expression;
use crate::ast::identifier::ASTIdentifier;
use crate::ast::span::Span;

#[derive(Debug, Clone)]
pub(crate) struct Item {
    pub(crate) identifier: ASTIdentifier,
    pub(crate) expression: Expression,
    pub(crate) span: Span,
}
