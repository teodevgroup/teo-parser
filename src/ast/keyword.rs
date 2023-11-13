use std::fmt::{Display, Formatter};
use crate::{declare_node, impl_node_defaults};
use crate::ast::span::Span;

declare_node!(Keyword, pub(crate) name: String);

impl_node_defaults!(Keyword);

impl Display for Keyword {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())?;
        f.write_str(" ")
    }
}

impl Keyword {

    pub(crate) fn new(name: &'static str, span: Span, path: Vec<usize>) -> Self {
        Self {
            span,
            path,
            name: name.to_owned(),
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn is_connector(&self) -> bool {
        self.name.as_str() == "connector"
    }

    pub fn is_server(&self) -> bool {
        self.name.as_str() == "server"
    }

    pub fn is_entity(&self) -> bool {
        self.name.as_str() == "entity"
    }

    pub fn is_client(&self) -> bool {
        self.name.as_str() == "client"
    }

    pub fn is_test(&self) -> bool {
        self.name.as_str() == "tests"
    }

    pub fn is_debug(&self) -> bool {
        self.name.as_str() == "debug"
    }
}
