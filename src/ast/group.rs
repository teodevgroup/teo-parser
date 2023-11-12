use std::fmt::{Display, Formatter};
use crate::ast::expression::{Expression, ExpressionKind};
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};

/// A group represents something like this (1 + 2) * 5
///
declare_container_node!(Group, pub(crate) expression: usize);

impl_container_node_defaults!(Group);

impl Group {

    node_child_fn!(expression, Expression);
}

impl Display for Group {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        Display::fmt(self.expression.as_ref(), f)?;
        f.write_str(")")
    }
}