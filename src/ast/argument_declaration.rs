use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct ArgumentListDeclaration {
    pub(crate) span: Span,
    pub(crate) argument_declarations: Vec<ArgumentDeclaration>,
}

impl ArgumentListDeclaration {

    pub(crate) fn every_argument_is_optional(&self) -> bool {
        for argument_declaration in &self.argument_declarations {
            if !argument_declaration.type_expr.resolved().is_optional() {
                return false
            }
        }
        true
    }

    pub(crate) fn get(&self, name: &str) -> Option<&ArgumentDeclaration> {
        self.argument_declarations.iter().find(|d| d.name.name() == name)
    }
}

#[derive(Debug)]
pub(crate) struct ArgumentDeclaration {
    pub(crate) span: Span,
    pub(crate) name: Identifier,
    pub(crate) name_optional: bool,
    pub(crate) type_expr: TypeExpr,
}

impl ArgumentListDeclaration {


}