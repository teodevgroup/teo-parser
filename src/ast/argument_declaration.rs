use crate::ast::identifier::Identifier;
use crate::ast::r#type::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct ArgumentListDeclaration {
    pub(crate) span: Span,
    pub(crate) argument_declarations: Vec<ArgumentDeclaration>,
}

#[derive(Debug)]
pub(crate) struct ArgumentDeclaration {
    pub(crate) span: Span,
    pub(crate) name: Identifier,
    pub(crate) name_optional: bool,
    pub(crate) type_expr: TypeExpr,
}