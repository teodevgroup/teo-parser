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

impl Display for Subscript {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("[")?;
        Display::fmt(self.expression.as_ref(), f)?;
        f.write_str("]")
    }
}

impl Write for Subscript {
    fn write(&self, writer: &mut Writer) {
        writer.write_children(self, self.children.values());
    }
}
