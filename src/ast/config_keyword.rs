use crate::{declare_node, impl_node_defaults_with_display};

declare_node!(ConfigKeyword, pub(crate) name: String);

impl_node_defaults_with_display!(ConfigKeyword, name);

impl ConfigKeyword {

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn is_connector(&self) -> bool {
        self.name.as_str() == "connector"
    }

    pub fn is_server(&self) -> bool {
        self.name.as_str() == "server"
    }

    pub fn is_entity(&self) -> bool {
        self.name.as_str() == "entity"
    }

    pub fn is_client(&self) -> bool {
        self.name.as_str() == "client"
    }

    pub fn is_test(&self) -> bool {
        self.name.as_str() == "tests"
    }

    pub fn is_debug(&self) -> bool {
        self.name.as_str() == "debug"
    }
}
