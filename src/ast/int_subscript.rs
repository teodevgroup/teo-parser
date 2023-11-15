use crate::{declare_node, impl_node_defaults};
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(IntSubscript, pub index: usize, pub(crate) index_string: String);

impl_node_defaults!(IntSubscript);

impl Write for IntSubscript {
    fn write(&self, writer: &mut Writer) {
        writer.write_contents(self, vec![".", self.index_string.as_str()])
    }
}
