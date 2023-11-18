use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::format::Writer;
use crate::traits::write::Write;
use crate::ast::expression::Expression;

declare_container_node!(NamedExpression, availability, pub(crate) key: usize, pub(crate) value: usize, pub(crate) is_config_field: bool, pub(crate) namespace_path: Vec<usize>);

impl_container_node_defaults!(NamedExpression, availability);

impl NamedExpression {
    node_child_fn!(key, Expression);
    node_child_fn!(value, Expression);
}

impl Write for NamedExpression {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}