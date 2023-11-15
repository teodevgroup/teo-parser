use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::format::Writer;
use crate::traits::node_trait::NodeTrait;
use crate::traits::write::Write;

declare_container_node!(ArgumentDeclaration,
    pub(crate) name: usize,
    pub(crate) name_optional: bool,
    pub(crate) type_expr: usize
);

impl_container_node_defaults!(ArgumentDeclaration);

impl ArgumentDeclaration {

    node_child_fn!(name, Identifier);

    node_child_fn!(type_expr, TypeExpr);
}

impl Write for ArgumentDeclaration {
    fn write(&self, writer: &mut Writer) {
        writer.write_children(self, self.children.values());
    }
}