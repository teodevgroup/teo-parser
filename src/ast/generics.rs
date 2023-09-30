use crate::ast::identifier::Identifier;
use crate::ast::r#type::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct GenericsDeclaration {
    pub(crate) span: Span,
    pub(crate) identifiers: Vec<Identifier>,
}

#[derive(Debug)]
pub struct GenericsConstraint {
    pub(crate) span: Span,
    pub(crate) items: Vec<GenericsConstraintItem>
}

#[derive(Debug)]
pub struct GenericsConstraintItem {
    pub(crate) span: Span,
    pub(crate) identifier: Identifier,
    pub(crate) type_expr: TypeExpr,
}