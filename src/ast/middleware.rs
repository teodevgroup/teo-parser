use crate::ast::argument_list::ArgumentList;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct Middleware {
    pub(crate) path: Vec<usize>,
    pub(crate) identifier: Identifier,
    pub(crate) argument_list: Option<ArgumentList>,
    pub(crate) span: Span,
}

impl Middleware {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }
}