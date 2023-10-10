use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use teo_teon::value::Value;
use crate::ast::expr::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::Type;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Argument {
    pub(crate) name: Option<Identifier>,
    pub(crate) value: Expression,
    pub(crate) span: Span,
    pub(crate) resolved: RefCell<Option<ArgumentResolved>>,
}

impl Argument {

    pub fn get_type(&self) -> &Type {
        let r = unsafe { &*self.value.resolved.as_ptr() };
        r.as_ref().unwrap().as_type().unwrap()
    }

    pub(crate) fn resolve(&self, resolved: ArgumentResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub(crate) fn resolved(&self) -> &ArgumentResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub(crate) fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }

    pub(crate) fn resolved_name(&self) -> Option<&str> {
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
    pub name: String
}
