use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::format::Writer;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::write::Write;

declare_container_node!(ConfigItem, named, availability,
    pub identifier: usize,
    pub expression: usize,
);

impl_container_node_defaults!(ConfigItem, named, availability);

impl ConfigItem {

    node_child_fn!(identifier, Identifier);

    node_child_fn!(expression, Expression);
}

impl InfoProvider for ConfigItem {

    fn namespace_skip(&self) -> usize {
        2
    }
}

impl Write for ConfigItem {
    fn write(&self, writer: &mut Writer) {
        writer.write_children(self, self.children.values());
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}