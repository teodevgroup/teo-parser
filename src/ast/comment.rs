use std::fmt::{Display, Formatter};
use serde::Serialize;
use crate::ast::span::Span;
use crate::impl_node_defaults;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct Comment {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) name: Option<String>,
    pub(crate) desc: Option<String>,
}

impl_node_defaults!(Comment);

impl Comment {

    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(|n| n.as_str())
    }

    pub fn desc(&self) -> Option<&str> {
        self.desc.as_ref().map(|n| n.as_str())
    }
}

impl Display for Comment {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = self.name() {
            f.write_fmt(format_args!("/// @name {}\n", name))?;
        }
        if let Some(desc) = self.desc() {
            f.write_fmt(format_args!("/// {}", desc))?;
        }
        Ok(())
    }
}