use crate::ast::node::Node;
use crate::ast::span::Span;
use crate::traits::identifiable::Identifiable;

pub trait NodeTrait: Identifiable {

    fn span(&self) -> Span;

    fn has_children(&self) -> bool;

    fn child(&self, id: usize) -> Option<Node>;

    fn children(&self) -> Vec<Node>;
}