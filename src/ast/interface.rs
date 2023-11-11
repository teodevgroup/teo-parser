use std::cell::RefCell;
use indexmap::{IndexMap, indexmap};
use serde::{Serialize, Serializer};
use crate::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::field::Field;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;
use crate::r#type::Type;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;

#[derive(Debug)]
pub struct InterfaceDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub generics_declaration: Option<GenericsDeclaration>,
    pub generics_constraint: Option<GenericsConstraint>,
    pub extends: Vec<TypeExpr>,
    pub fields: Vec<Field>,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
    pub shape_resolved: RefCell<Option<InterfaceDeclarationShapeResolved>>,
}

impl InterfaceDeclaration {

    pub fn extends(&self) -> &Vec<TypeExpr> {
        &self.extends
    }

    pub fn shape_resolved(&self) -> &InterfaceDeclarationShapeResolved {
        (unsafe { &*self.shape_resolved.as_ptr() }).as_ref().unwrap()
    }

    fn shape_resolved_mut(&self) -> &mut InterfaceDeclarationShapeResolved {
        (unsafe { &mut *self.shape_resolved.as_ptr() }).as_mut().unwrap()
    }

    pub fn shape(&self, generics: &Vec<Type>) -> Option<&Type> {
        self.shape_resolved().map.get(generics)
    }

    pub fn set_shape(&self, generics: Vec<Type>, input: Type) {
        self.shape_resolved_mut().map.insert(generics, input);
    }
}

impl Identifiable for InterfaceDeclaration {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for InterfaceDeclaration {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for InterfaceDeclaration {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for InterfaceDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}

#[derive(Debug, Clone)]
pub struct InterfaceDeclarationShapeResolved {
    pub map: IndexMap<Vec<Type>, Type>,
}

#[derive(Serialize)]
pub struct InterfaceDeclarationShapeResolvedItemRef<'a> {
    key: &'a Vec<Type>,
    value: &'a Type,
}

impl Serialize for InterfaceDeclarationShapeResolved {

    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.collect_seq(self.map.iter().map(|(key, value)| InterfaceDeclarationShapeResolvedItemRef {
            key,
            value
        }))
    }
}

impl InterfaceDeclarationShapeResolved {

    pub fn new() -> Self {
        Self {
            map: indexmap! {}
        }
    }
}