use std::fmt::Display;
use crate::ast::node::Node;
use crate::ast::span::Span;
use crate::traits::identifiable::Identifiable;

pub trait NodeTrait: Identifiable + Display {

    fn span(&self) -> Span;

    fn children(&self) -> &Vec<Node>;

    fn has_children(&self) -> bool {
        self.children().is_empty()
    }

    fn child(&self, id: usize) -> Option<&Node> {
        self.children().iter().find(|c| c.id() == id)
    }
}