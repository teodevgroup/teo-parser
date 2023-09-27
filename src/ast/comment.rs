use crate::ast::span::Span;

#[derive(Debug)]
pub struct Comment {
    pub(crate) span: Span,
    pub(crate) name: Option<String>,
    pub(crate) desc: Option<String>,
}

impl Comment {

    pub(crate) fn name(&self) -> Option<&str> {
        self.name.as_ref().map(|n| n.as_str())
    }

    pub(crate) fn desc(&self) -> Option<&str> {
        self.desc.as_ref().map(|n| n.as_str())
    }
}