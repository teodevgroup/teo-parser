use crate::{declare_node, impl_node_defaults};
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(AvailabilityFlag, pub(crate) name: String);

impl_node_defaults!(AvailabilityFlag);

impl Write for AvailabilityFlag {

    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_contents(self, vec!["#if available(", self.name.as_str(), ")\n"]);
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}