use std::fmt::Display;
use crate::{declare_node, impl_node_defaults};
use crate::ast::span::Span;
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(Punctuation, content: &'static str);

impl Punctuation {

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

impl Write for Punctuation {

    fn write(&self, writer: &mut Writer) {
        writer.write(self, self.content());
    }

    fn prefer_whitespace_before(&self) -> bool {
        match self.content() {
            "@" | "}" => true,
            _ => false,
        }
    }

    fn prefer_whitespace_after(&self) -> bool {
        match self.content() {
            "," | ":" | "{" => true,
            _ => false,
        }
    }

    fn prefer_always_no_whitespace_before(&self) -> bool {
        match self.content() {
            ")" | "]" => true,
            _ => false,
        }
    }

    fn is_block_start(&self) -> bool {
        match self.content() {
            "(" | "[" | "{" => true,
            _ => false,
        }
    }

    fn is_block_end(&self) -> bool {
        match self.content() {
            ")" | "]" | "}" => true,
            _ => false,
        }
    }
}
