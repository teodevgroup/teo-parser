use std::collections::BTreeMap;
use std::fmt::Display;
use crate::ast::node::Node;
use crate::ast::span::Span;
use crate::traits::identifiable::Identifiable;
use crate::traits::write::Write;

pub trait NodeTrait: Identifiable + Write + Display {

    fn span(&self) -> Span;

    fn children(&self) -> Option<&BTreeMap<usize, Node>>;

    fn has_children(&self) -> bool {
        self.children().map_or(false, |c| c.is_empty())
    }

    fn child(&self, id: usize) -> Option<&Node> {
        self.children().map(|c| c.get(&id)).flatten()
    }
}