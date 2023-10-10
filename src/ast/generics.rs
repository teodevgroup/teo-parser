use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct GenericsDeclaration {
    pub(crate) span: Span,
    pub(crate) identifiers: Vec<Identifier>,
}

impl GenericsDeclaration {

    pub(crate) fn names(&self) -> Vec<&str> {
        self.identifiers.iter().map(|i| i.name()).collect()
    }
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