use crate::{declare_node, impl_node_defaults};
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(EmptyDecorator);

impl_node_defaults!(EmptyDecorator);

impl EmptyDecorator { }

impl Write for EmptyDecorator {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_content(self, "@");
    }
}
