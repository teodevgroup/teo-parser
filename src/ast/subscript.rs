use std::fmt::{Display, Formatter};
use crate::ast::expression::Expression;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::format::Writer;
use crate::traits::write::Write;

declare_container_node!(Subscript,
    pub(crate) expression: usize,
);

impl_container_node_defaults!(Subscript);

impl Subscript {

    node_child_fn!(expression, Expression);
}

impl Write for Subscript {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}
