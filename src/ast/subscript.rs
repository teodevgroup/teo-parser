use std::fmt::{Display, Formatter};
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Subscript {
    pub expression: Box<Expression>,
    pub span: Span,
}

impl Display for Subscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("[")?;
        Display::fmt(self.expression.as_ref(), f)?;
        f.write_str("]")
    }
}
