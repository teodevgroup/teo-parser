use std::cell::RefCell;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::field::Field;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;

#[derive(Debug)]
pub struct ConfigDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub fields: Vec<Field>,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
}

impl ConfigDeclaration {
    
    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    pub fn get_field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.identifier.name() == name)
    }
}

impl Identifiable for ConfigDeclaration {

    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for ConfigDeclaration {

    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for ConfigDeclaration {

    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        self.actual_availability.borrow().clone()
    }
}

impl InfoProvider for ConfigDeclaration {

    fn namespace_skip(&self) -> usize {
        1
    }
}