use std::fmt::{Display, Formatter};
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct Unit {
    pub(crate) expressions: Vec<Expression>,
    pub(crate) span: Span,
}

impl Display for Unit {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (index, item) in self.expressions.iter().enumerate() {
            if index != 0 {
                if item.kind.as_identifier().is_some() {
                    f.write_str(".")?;
                }
            }
            Display::fmt(&item, f)?;
        }
        Ok(())
    }
}
