use std::fmt::{Display, Formatter};
use crate::ast::expression::Expression;
use crate::ast::span::Span;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};

declare_container_node!(Subscript,
    pub(crate) expression: usize,
);

impl_container_node_defaults!(Subscript);

impl Subscript {

    node_child_fn!(expression, Expression);
}

impl Display for Subscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("[")?;
        Display::fmt(self.expression.as_ref(), f)?;
        f.write_str("]")
    }
}
