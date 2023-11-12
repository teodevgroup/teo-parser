use std::fmt::{Display, Formatter};
use crate::{declare_container_node, impl_container_node_defaults, node_children_iter, node_children_iter_fn};
use crate::traits::node_trait::NodeTrait;
use super::identifier::Identifier;

declare_container_node!(IdentifierPath, pub(crate) identifiers: Vec<usize>);

impl_container_node_defaults!(IdentifierPath);

node_children_iter!(IdentifierPath, Identifier, IdentifiersIter, identifiers);

impl IdentifierPath {

    node_children_iter_fn!(identifiers, IdentifiersIter);

    pub fn names(&self) -> Vec<&str> {
        self.identifiers().map(|i| i.name()).collect()
    }
}

impl Display for IdentifierPath {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, id) in self.identifiers.enumerate() {
            if i != 0 {
                f.write_str(".")?;
            }
            Display::fmt(&id, f)?;
        }
        Ok(())
    }
}