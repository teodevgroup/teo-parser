use crate::{declare_node, impl_node_defaults};
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(EmptyPipeline);

impl_node_defaults!(EmptyPipeline);

impl EmptyPipeline { }

impl Write for EmptyPipeline {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_content(self, "$");
    }
}
