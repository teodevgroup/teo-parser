use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct GenericsDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) identifiers: Vec<Identifier>,
}

impl GenericsDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

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