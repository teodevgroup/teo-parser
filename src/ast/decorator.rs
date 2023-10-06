use std::cell::RefCell;
use crate::ast::argument_list::ArgumentList;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct DecoratorResolved {
    pub(crate) path: Vec<usize>,
}

#[derive(Debug)]
pub struct Decorator {
    pub(crate) span: Span,
    pub(crate) identifier_path: IdentifierPath,
    pub(crate) argument_list: Option<ArgumentList>,
    pub(crate) resolved: RefCell<Option<DecoratorResolved>>,
}

impl Decorator {

    pub(crate) fn resolve(&self, resolved: DecoratorResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub(crate) fn resolved(&self) -> &DecoratorResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub(crate) fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}
