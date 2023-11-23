use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::ast::identifier::Identifier;
use crate::ast::punctuations::Punctuation;
use crate::format::Writer;
use crate::traits::write::Write;

declare_container_node!(PartialArgument,
    pub(crate) name: usize,
    pub(crate) colon: usize,
);

impl_container_node_defaults!(PartialArgument);

impl PartialArgument {
    node_child_fn!(name, Identifier);
    node_child_fn!(colon, Punctuation);
}

impl Write for PartialArgument {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}
