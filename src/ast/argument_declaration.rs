use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;
use crate::{declare_container_node, impl_container_node_defaults, impl_container_node_defaults_with_display, node_child_fn};

declare_container_node!(ArgumentDeclaration, name: usize, name_optional: bool, type_expr: usize);

impl ArgumentDeclaration {

    node_child_fn!(name, Identifier, as_identifier);

    node_child_fn!(type_expr, TypeExpr, as_type_expr);
}

impl_container_node_defaults_with_display!(ArgumentDeclaration);