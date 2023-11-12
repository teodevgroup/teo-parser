use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn};

declare_container_node!(GenericsDeclaration,
    pub(crate) identifiers: Vec<usize>,
);

impl_container_node_defaults!(GenericsDeclaration);

node_children_iter!(GenericsDeclaration, Identifier, IdentifiersIter, identifiers);

impl GenericsDeclaration {

    node_children_iter_fn!(identifiers, IdentifiersIter);

    pub fn names(&self) -> Vec<&str> {
        self.identifiers().map(|i| i.name()).collect()
    }
}

declare_container_node!(GenericsConstraint, pub(crate) items: Vec<usize>);

impl_container_node_defaults!(GenericsConstraint);

node_children_iter!(GenericsConstraint, GenericsConstraintItem, ItemsIter, items);

impl GenericsConstraint {

    node_children_iter_fn!(items, ItemsIter);
}

declare_container_node!(GenericsConstraintItem, pub(crate) identifier: usize, pub(crate) type_expr: usize);

impl_container_node_defaults!(GenericsConstraintItem);

impl GenericsConstraintItem {

    node_child_fn!(identifier, Identifier);

    node_child_fn!(type_expr, TypeExpr);
}
