use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::ast::type_expr::TypeExpr;
use crate::format::Writer;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(TypeAsValueExpression,
    pub(crate) type_expr: usize,
);

impl_container_node_defaults!(TypeAsValueExpression);

impl TypeAsValueExpression {

    node_child_fn!(type_expr, TypeExpr);
}

impl Write for TypeAsValueExpression {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}
