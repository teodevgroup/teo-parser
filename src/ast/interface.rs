use std::cell::RefCell;
use indexmap::{IndexMap, indexmap};
use serde::Serialize;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::field::Field;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifiable::Identifiable;
use crate::ast::identifier::Identifier;
use crate::ast::info_provider::InfoProvider;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;
use crate::r#type::Type;
use crate::shape::input::Input;

#[derive(Debug)]
pub struct InterfaceDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub define_availability: Availability,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub generics_declaration: Option<GenericsDeclaration>,
    pub generics_constraint: Option<GenericsConstraint>,
    pub extends: Vec<TypeExpr>,
    pub fields: Vec<Field>,
    pub resolved: RefCell<Option<InterfaceDeclarationResolved>>,
    pub shape_resolved: RefCell<Option<InterfaceDeclarationShapeResolved>>,
}

impl InterfaceDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn extends(&self) -> &Vec<TypeExpr> {
        &self.extends
    }

    pub fn is_available(&self) -> bool {
        self.define_availability.contains(self.resolved().actual_availability)
    }

    pub fn resolve(&self, resolved: InterfaceDeclarationResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &InterfaceDeclarationResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn shape_resolved(&self) -> &InterfaceDeclarationShapeResolved {
        (unsafe { &*self.shape_resolved.as_ptr() }).as_ref().unwrap()
    }

    fn shape_resolved_mut(&self) -> &mut InterfaceDeclarationShapeResolved {
        (unsafe { &mut *self.shape_resolved.as_ptr() }).as_mut().unwrap()
    }

    pub fn shape(&self, generics: &Vec<Type>) -> Option<&Input> {
        self.shape_resolved().map.get(generics)
    }

    pub fn set_shape(&self, generics: Vec<Type>, input: Input) {
        self.shape_resolved_mut().map.insert(generics, input);
    }
}

#[derive(Debug)]
pub struct InterfaceDeclarationResolved {
    pub actual_availability: Availability,
}

impl Identifiable for InterfaceDeclaration {

    fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    fn path(&self) -> &Vec<usize> {
        &self.path
    }

    fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }
}

impl InfoProvider for InterfaceDeclaration {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceDeclarationShapeResolved {
    pub map: IndexMap<Vec<Type>, Input>,
}

impl InterfaceDeclarationShapeResolved {

    pub fn new() -> Self {
        Self {
            map: indexmap! {}
        }
    }
}