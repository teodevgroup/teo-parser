use std::fmt::{Display, Formatter};
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Unit {
    pub expressions: Vec<Expression>,
    pub span: Span,
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

impl Unit {

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        if self.expressions.len() != 1 {
            None
        } else {
            self.expressions.first().unwrap().unwrap_enumerable_enum_member_strings()
        }
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        if self.expressions.len() != 1 {
            None
        } else {
            self.expressions.first().unwrap().unwrap_enumerable_enum_member_string()
        }
    }
}