use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::span::Span;
use crate::ast::unit::Unit;

#[derive(Debug)]
pub(crate) struct Pipeline {
    pub(crate) unit: Box<Unit>,
    pub(crate) span: Span,
    pub(crate) resolved: RefCell<Option<PipelineResolved>>,
}

impl Pipeline {

    pub(crate) fn resolve(&self, resolved: PipelineResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub(crate) fn resolved(&self) -> &PipelineResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub(crate) fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

impl Display for Pipeline {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("$")?;
        Display::fmt(&self.unit, f)
    }
}

#[derive(Debug)]
pub struct PipelineResolved {
    pub items: Vec<Item>
}

#[derive(Debug)]
pub struct Item {
    pub path_start: usize,
    pub path_end: usize,
    pub argument_list: Option<usize>,
}