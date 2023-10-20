use std::cell::RefCell;
use crate::ast::argument_list::ArgumentList;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct DecoratorResolved {
    pub path: Vec<usize>,
}

#[derive(Debug)]
pub struct Decorator {
    pub span: Span,
    pub identifier_path: IdentifierPath,
    pub argument_list: Option<ArgumentList>,
    pub resolved: RefCell<Option<DecoratorResolved>>,
}

impl Decorator {

    pub(crate) fn resolve(&self, resolved: DecoratorResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &DecoratorResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}
