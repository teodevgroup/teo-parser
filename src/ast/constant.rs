use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::accessible::Accessible;
use crate::ast::expr::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct ConstantResolved {
    accessible: Accessible,
}

#[derive(Debug)]
pub(crate) struct Constant {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) identifier: Identifier,
    pub(crate) expression: Expression,
    pub(crate) resolved: RefCell<Option<ConstantResolved>>,
}

impl Constant {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub(crate) fn
}

impl Display for Constant {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("let ")?;
        Display::fmt(&self.identifier, f)?;
        f.write_str(" = ")?;
        Display::fmt(&self.expression, f)
    }
}
