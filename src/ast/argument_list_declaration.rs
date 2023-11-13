use crate::{declare_container_node, impl_container_node_defaults, impl_container_node_defaults_with_display, node_children_iter, node_children_iter_fn};
use crate::ast::argument_declaration::ArgumentDeclaration;

declare_container_node!(ArgumentListDeclaration, pub(crate) argument_declarations: Vec<usize>);

impl_container_node_defaults_with_display!(ArgumentListDeclaration);

node_children_iter!(
    ArgumentListDeclaration,
    ArgumentDeclaration,
    ArgumentDeclarationsIter,
    argument_declarations
);

impl ArgumentListDeclaration {

    node_children_iter_fn!(argument_declarations, ArgumentDeclarationsIter);

    pub fn every_argument_is_optional(&self) -> bool {
        for argument_declaration in self.argument_declarations() {
            if !argument_declaration.type_expr().resolved().is_optional() {
                return false
            }
        }
        true
    }

    pub fn get(&self, name: &str) -> Option<&ArgumentDeclaration> {
        self.argument_declarations().find(|d| d.name().name() == name)
    }
}