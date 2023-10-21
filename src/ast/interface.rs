use std::cell::RefCell;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::field::Field;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::info_provider::InfoProvider;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct InterfaceDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) define_availability: Availability,
    pub comment: Option<Comment>,
    pub(crate) identifier: Identifier,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
    pub(crate) extends: Vec<TypeExpr>,
    pub(crate) fields: Vec<Field>,
        pub(crate) resolved: RefCell<Option<InterfaceDeclarationResolved>>
}

impl InterfaceDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub(crate) fn extends(&self) -> &Vec<TypeExpr> {
        &self.extends
    }

    pub fn is_available(&self) -> bool {
        self.define_availability.contains(self.resolved().actual_availability)
    }

    pub(crate) fn resolve(&self, resolved: InterfaceDeclarationResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub(crate) fn resolved(&self) -> &InterfaceDeclarationResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub(crate) fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

#[derive(Debug)]
pub struct InterfaceDeclarationResolved {
    pub(crate) actual_availability: Availability,
}

impl InfoProvider for &InterfaceDeclaration {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}