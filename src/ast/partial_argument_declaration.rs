use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_optional_child_fn};
use crate::ast::identifier::Identifier;
use crate::ast::punctuations::Punctuation;
use crate::format::Writer;
use crate::traits::write::Write;

declare_container_node!(PartialArgumentDeclaration,
    pub(crate) identifier: usize,
    pub(crate) optional: Option<usize>,
    pub(crate) colon: usize
);

impl_container_node_defaults!(PartialArgumentDeclaration);

impl PartialArgumentDeclaration {
    node_child_fn!(identifier, Identifier);
    node_optional_child_fn!(optional, Punctuation);
    node_child_fn!(colon, Punctuation);
}

impl Write for PartialArgumentDeclaration {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}
