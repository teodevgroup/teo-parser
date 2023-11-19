use crate::ast::expression::{Expression};
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::format::Writer;
use crate::traits::write::Write;

declare_container_node!(Group, pub(crate) expression: usize);

impl_container_node_defaults!(Group);

impl Group {

    node_child_fn!(expression, Expression);
}

impl Write for Group {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }
}