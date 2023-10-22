use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct GenericsDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub identifiers: Vec<Identifier>,
}

impl GenericsDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn names(&self) -> Vec<&str> {
        self.identifiers.iter().map(|i| i.name()).collect()
    }
}

#[derive(Debug)]
pub struct GenericsConstraint {
    pub span: Span,
    pub items: Vec<GenericsConstraintItem>
}

#[derive(Debug)]
pub struct GenericsConstraintItem {
    pub span: Span,
    pub identifier: Identifier,
    pub type_expr: TypeExpr,
}