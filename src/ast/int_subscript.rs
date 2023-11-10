use std::fmt::{Display, Formatter};
use crate::ast::span::Span;

#[derive(Debug)]
pub struct IntSubscript {
    pub span: Span,
    pub index: usize,
}

impl Display for IntSubscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(".")?;
        Display::fmt(&self.index, f)
    }
}
