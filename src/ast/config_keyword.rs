use crate::ast::span::Span;

#[derive(Debug)]
pub struct ConfigKeyword {
    pub span: Span,
    pub name: String,
}

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
