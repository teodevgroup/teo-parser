use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::format::Writer;
use crate::traits::write::Write;
use crate::ast::expression::Expression;

declare_container_node!(BracketExpression, pub(crate) expression: usize);

impl_container_node_defaults!(BracketExpression);

impl BracketExpression {
    node_child_fn!(expression, Expression);
}

impl Write for BracketExpression {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}