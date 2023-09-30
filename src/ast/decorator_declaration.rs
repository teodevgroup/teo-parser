use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::comment::Comment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct DecoratorDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) unique: bool,
    pub(crate) decorator_class: ReferenceType,
    pub(crate) identifier: Identifier,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
    pub(crate) variants: Vec<DecoratorVariant>,
}

impl DecoratorDeclaration {

    pub(crate) fn has_variants(&self) -> bool {
        !self.variants.is_empty()
    }
}

#[derive(Debug)]
pub(crate) struct DecoratorVariant {
    pub(crate) span: Span,
    pub(crate) comment: Option<Comment>,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
}
