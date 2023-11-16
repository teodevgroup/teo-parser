use crate::{declare_node, impl_node_defaults};
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(Identifier, pub(crate) name: String);

impl Identifier {

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl_node_defaults!(Identifier);

impl Write for Identifier {
    fn write(&self, writer: &mut Writer) {
        writer.write_content(self, self.name());
    }
}

