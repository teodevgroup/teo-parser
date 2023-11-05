use std::cell::RefCell;
use crate::ast::availability::Availability;
use crate::ast::expression::Expression;
use crate::ast::identifiable::Identifiable;
use crate::ast::identifier::Identifier;
use crate::ast::info_provider::InfoProvider;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct ConfigItem {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub identifier: Identifier,
    pub expression: Expression,
    pub define_availability: Availability,
    pub resolved: RefCell<Option<ConfigItemResolved>>,
}

impl ConfigItem {

    pub fn resolve(&self, resolved: ConfigItemResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &ConfigItemResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }

    pub fn is_available(&self) -> bool {
        self.define_availability.contains(self.resolved().actual_availability)
    }
}

impl Identifiable for ConfigItem {

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

impl InfoProvider for ConfigItem {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(2).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}

#[derive(Debug)]
pub struct ConfigItemResolved {
    pub actual_availability: Availability
}