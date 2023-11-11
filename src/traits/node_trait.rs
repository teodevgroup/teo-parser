use std::fmt::Display;
use crate::ast::node::Node;
use crate::ast::span::Span;
use crate::traits::identifiable::Identifiable;

pub trait NodeTrait: Identifiable + Display {

    fn span(&self) -> Span;

    fn children(&self) -> Option<&Vec<Node>>;

    fn has_children(&self) -> bool {
        self.children().map_or(false, |c| c.is_empty())
    }

    fn child(&self, id: usize) -> Option<&Node> {
        self.children().map(|c| c.iter().find(|c| c.id() == id)).flatten()
    }
}