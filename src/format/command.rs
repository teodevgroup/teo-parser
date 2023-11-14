use crate::traits::write::Write;

pub(super) struct Command<'a> {
    node: &'a dyn Write,
    content: &'a str,
}

impl<'a> Command<'a> {

    pub(super) fn new(node: &'a dyn Write, content: &'a str) -> Self {
        Self { node, content }
    }

    pub(super) fn node(&'a self) -> &'a dyn Write {
        self.node
    }

    pub(super) fn content(&'a self) -> &'a str {
        self.content
    }
}