use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::ast::identifier::Identifier;
use crate::ast::punctuations::Punctuation;
use crate::format::Writer;
use crate::traits::write::Write;

declare_container_node!(PartialField, pub(crate) identifier: usize, pub(crate) colon: usize);

impl_container_node_defaults!(PartialField);

impl PartialField {
    node_child_fn!(identifier, Identifier);
    node_child_fn!(colon, Punctuation);
}

impl Write for PartialField {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_content(self, ".");
    }
}
