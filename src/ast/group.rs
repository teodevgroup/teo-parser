use std::fmt::{Display, Formatter};
use crate::ast::expr::ExpressionKind;
use crate::ast::span::Span;

/// A group represents something like this (1 + 2) * 5
#[derive(Debug)]
pub(crate) struct Group {
    pub(crate) expression: Box<ExpressionKind>,
    pub(crate) span: Span,
}

impl Display for Group {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        Display::fmt(self.expression.as_ref(), f)?;
        f.write_str(")")
    }
}