use std::cell::RefCell;
use crate::ast::argument_list::ArgumentList;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;
use crate::completion::completion::CompletionItem;
use crate::completion::completion_context::CompletionContext;

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

    pub(crate) fn find_auto_complete_items<'a>(&'a self, context: &mut CompletionContext<'a>, line_col: (usize, usize), reference_type: ReferenceType) -> Vec<CompletionItem> {
        vec![]
    }
}
