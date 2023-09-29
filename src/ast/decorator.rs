use std::cell::RefCell;
use crate::ast::argument_list::ArgumentList;
use crate::ast::span::Span;
use crate::ast::unit::Unit;

#[derive(Debug)]
pub struct DecoratorResolved {
    pub(crate) path: Vec<usize>,
    pub(crate) arguments: ArgumentList,
}

#[derive(Debug)]
pub struct Decorator {
    pub(crate) span: Span,
    pub(crate) unit: Unit,
    pub(crate) resolved: RefCell<Option<DecoratorResolved>>,
}

impl Decorator {

    pub(crate) fn resolved(&self) -> &DecoratorResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }
}
