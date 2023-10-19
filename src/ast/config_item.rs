use std::cell::RefCell;
use crate::ast::availability::Availability;
use crate::ast::expr::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct ConfigItem {
    pub span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub identifier: Identifier,
    pub expression: Expression,
    pub define_availability: Availability,
    pub(crate) resolved: RefCell<Option<ConfigItemResolved>>,
}

impl ConfigItem {

    pub(crate) fn resolve(&self, resolved: ConfigItemResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub(crate) fn resolved(&self) -> &ConfigItemResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub(crate) fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }

    pub fn is_available(&self) -> bool {
        self.define_availability.contains(self.resolved().actual_availability)
    }
}

#[derive(Debug)]
pub(crate) struct ConfigItemResolved {
    pub(crate) actual_availability: Availability
}