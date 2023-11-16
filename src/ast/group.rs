use std::fmt::{Display, Formatter};
use crate::ast::expression::{Expression, ExpressionKind};
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::format::Writer;
use crate::traits::write::Write;

/// A group represents something like this (1 + 2) * 5
///
declare_container_node!(Group, pub(crate) expression: usize);

impl_container_node_defaults!(Group);

impl Group {

    node_child_fn!(expression, Expression);
}

impl Write for Group {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }
}