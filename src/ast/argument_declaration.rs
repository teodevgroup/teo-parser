use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::{declare_container_node, impl_container_node_defaults_with_display, node_child_fn};

declare_container_node!(ArgumentDeclaration,
    pub(crate) name: usize,
    pub(crate) name_optional: bool,
    pub(crate) type_expr: usize
);

impl_container_node_defaults_with_display!(ArgumentDeclaration);

impl ArgumentDeclaration {

    node_child_fn!(name, Identifier);

    node_child_fn!(type_expr, TypeExpr);
}
