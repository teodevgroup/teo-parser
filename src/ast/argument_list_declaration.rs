use crate::{declare_container_node, impl_container_node_defaults, node_children_iter, node_children_iter_fn};
use crate::ast::argument_declaration::ArgumentDeclaration;
use crate::format::Writer;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(ArgumentListDeclaration, pub(crate) argument_declarations: Vec<usize>);

impl_container_node_defaults!(ArgumentListDeclaration);

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

impl Write for ArgumentListDeclaration {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}