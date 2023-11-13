use std::fmt::{Display, Formatter};
use crate::{declare_node, impl_node_defaults};
use crate::ast::span::Span;

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

impl Display for Punctuation {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.content() {
            ":" => ": ",
            "," => ", ",
            _ => self.content(),
        })
    }
}
