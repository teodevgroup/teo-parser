use std::fmt::Display;
use crate::{declare_node, impl_node_defaults};
use crate::ast::span::Span;
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(Operator, content: &'static str);

impl Operator {

    pub(crate) fn new(content: &'static str, span: Span, path: Vec<usize>) -> Self {
        Self {
            span,
            path,
            content
        }
    }

    pub fn content(&self) -> &str {
        self.content
    }
}

impl_node_defaults!(Punctuation);

impl Write for Operator {

    fn write(&self, writer: &mut Writer) {
        writer.write_content(self, self.content());
    }

    fn prefer_whitespace_before(&self) -> bool {
        match self.content() {
            "!" | "?" | ".." | "..." => false,
            _ => true,
        }
    }

    fn prefer_whitespace_after(&self) -> bool {
        match self.content() {
            "!" | "?" | ".." | "..." => false,
            _ => true,
        }
    }

    fn prefer_always_no_whitespace_before(&self) -> bool {
        match self.content() {
            "!" | "?" | ".." | "..." => true,
            _ => false,
        }
    }
}
