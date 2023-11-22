use crate::ast::unit::Unit;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::format::Writer;
use crate::traits::write::Write;

declare_container_node!(Pipeline, pub(crate) unit: usize);

impl_container_node_defaults!(Pipeline);

impl Pipeline {
    node_child_fn!(unit, Unit);
}

impl Write for Pipeline {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}
