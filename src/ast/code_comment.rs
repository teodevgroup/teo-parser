use serde::Serialize;
use crate::ast::span::Span;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct CodeComment {
    pub span: Span,
    pub lines: Vec<String>,
}

impl CodeComment {

    pub fn lines(&self) -> &Vec<String> {
        &self.lines
    }
}