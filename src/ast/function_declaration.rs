use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::call::Call;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::comment::Comment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct FunctionDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) r#static: bool,
    pub(crate) identifier: Identifier,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
    pub(crate) return_type: TypeExpr,
}

impl FunctionDeclaration {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub(crate) fn callable_variants(&self) -> Vec<CallableVariant> {
        vec![CallableVariant {
            generics_declaration: self.generics_declaration.as_ref(),
            argument_list_declaration: self.argument_list_declaration.as_ref(),
            generics_constraint: self.generics_constraint.as_ref(),
        }]
    }
}