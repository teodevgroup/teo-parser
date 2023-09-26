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