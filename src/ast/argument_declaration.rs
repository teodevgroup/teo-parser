use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct ArgumentListDeclaration {
    pub span: Span,
    pub argument_declarations: Vec<ArgumentDeclaration>,
}

impl ArgumentListDeclaration {

    pub fn every_argument_is_optional(&self) -> bool {
        for argument_declaration in &self.argument_declarations {
            if !argument_declaration.type_expr.resolved().is_optional() {
                return false
            }
        }
        true
    }

    pub fn get(&self, name: &str) -> Option<&ArgumentDeclaration> {
        self.argument_declarations.iter().find(|d| d.name.name() == name)
    }
}

#[derive(Debug)]
pub struct ArgumentDeclaration {
    pub span: Span,
    pub name: Identifier,
    pub name_optional: bool,
    pub type_expr: TypeExpr,
}

impl ArgumentListDeclaration {


}