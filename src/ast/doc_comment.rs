use std::fmt::{Display, Formatter};
use serde::Serialize;
use crate::ast::span::Span;
use crate::format::Writer;
use crate::impl_node_defaults;
use crate::traits::write::Write;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
pub struct DocComment {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) name: Option<String>,
    pub(crate) desc: Option<String>,
}

impl_node_defaults!(DocComment);

impl DocComment {

    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(|n| n.as_str())
    }

    pub fn desc(&self) -> Option<&str> {
        self.desc.as_ref().map(|n| n.as_str())
    }
}

impl Write for DocComment {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        let mut contents = vec![];
        if let Some(name) = self.name() {
            contents.push("/// @name ");
            contents.push(name);
            contents.push("\n");
        }
        if let Some(desc) = self.desc() {
            contents.push("/// ");
            contents.push(desc);
            contents.push("\n");
        }
        writer.write_contents(self, contents);

    }
}
