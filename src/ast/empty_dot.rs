use crate::{declare_node, impl_node_defaults};
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(EmptyDot);

impl_node_defaults!(EmptyDot);

impl EmptyDot { }

impl Write for EmptyDot {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_content(self, ".");
    }
}
