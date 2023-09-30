use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct ConfigKeyword {
    pub(crate) span: Span,
    pub(crate) name: String,
}

impl ConfigKeyword {

    pub(crate) fn name(&self) -> &str {
        self.name.as_str()
    }

    pub(crate) fn is_connector(&self) -> bool {
        self.name.as_str() == "connector"
    }

    pub(crate) fn is_server(&self) -> bool {
        self.name.as_str() == "server"
    }

    pub(crate) fn is_entity(&self) -> bool {
        self.name.as_str() == "entity"
    }

    pub(crate) fn is_client(&self) -> bool {
        self.name.as_str() == "client"
    }

    pub(crate) fn is_test(&self) -> bool {
        self.name.as_str() == "tests"
    }

    pub(crate) fn is_debug(&self) -> bool {
        self.name.as_str() == "debug"
    }
}
