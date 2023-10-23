use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::r#type::r#type::Type;

#[derive(Debug)]
pub struct Argument {
    pub name: Option<Identifier>,
    pub value: Expression,
    pub span: Span,
    pub resolved: RefCell<Option<ArgumentResolved>>,
}

impl Argument {

    pub fn get_type(&self) -> &Type {
        &self.value.resolved().r#type
    }

    pub fn resolve(&self, resolved: ArgumentResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &ArgumentResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }

    pub fn resolved_name(&self) -> Option<&str> {
        if let Some(name) = &self.name {
            Some(name.name())
        } else {
            if self.is_resolved() {
                Some(self.resolved().name.as_str())
            } else {
                None
            }
        }
    }
}

impl Display for Argument {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = &self.name {
            f.write_str(&name.name)?;
            f.write_str(": ")?;
        }
        Display::fmt(&self.value, f)
    }
}

#[derive(Debug)]
pub struct ArgumentResolved {
    pub name: String,
    pub expect: Type,
}
