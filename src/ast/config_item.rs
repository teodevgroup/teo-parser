use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;

#[derive(Debug)]
pub struct ConfigItem {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub identifier: Identifier,
    pub expression: Expression,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
}

impl Identifiable for ConfigItem {

    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for ConfigItem {

    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for ConfigItem {

    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for ConfigItem {

    fn namespace_skip(&self) -> usize {
        2
    }
}