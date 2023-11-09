use serde::Serialize;
use crate::ast::span::Span;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct Comment {
    pub span: Span,
    pub name: Option<String>,
    pub desc: Option<String>,
}

impl Comment {

    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(|n| n.as_str())
    }

    pub fn desc(&self) -> Option<&str> {
        self.desc.as_ref().map(|n| n.as_str())
    }
}