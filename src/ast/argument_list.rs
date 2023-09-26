use std::fmt::{Display, Formatter};
use crate::ast::argument::Argument;
use crate::ast::span::Span;

#[derive(Debug, Clone)]
pub struct ArgumentList {
    pub(crate) arguments: Vec<Argument>,
    pub(crate) span: Span,
}

impl ArgumentList {

    pub fn arguments(&self) -> &Vec<Argument> {
        &self.arguments
    }
}

impl Display for ArgumentList {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        let len = self.arguments.len();
        for (index, expression) in self.arguments.iter().enumerate() {
            Display::fmt(expression, f)?;
            if index != len - 1 {
                f.write_str(", ")?;
            }
        }
        f.write_str(")")
    }
}
