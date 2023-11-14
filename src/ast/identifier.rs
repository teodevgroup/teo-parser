use crate::{declare_node, impl_node_defaults_with_write};

declare_node!(Identifier, pub(crate) name: String);

impl Identifier {

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl_node_defaults_with_write!(Identifier, name);
