use crate::ast::action::ActionGroupDeclaration;
use crate::ast::config::Config;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::constant::Constant;
use crate::ast::data_set::DataSet;
use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::import::Import;
use crate::ast::interface::InterfaceDeclaration;
use crate::ast::middleware::Middleware;
use crate::ast::model::Model;
use crate::ast::namespace::Namespace;
use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::r#enum::Enum;

#[derive(Debug)]
pub(crate) enum Top {
    Import(Import),
    Config(Config),
    ConfigDeclaration(ConfigDeclaration),
    Constant(Constant),
    Enum(Enum),
    Model(Model),
    DataSet(DataSet),
    Middleware(Middleware),
    ActionGroup(ActionGroupDeclaration),
    Interface(InterfaceDeclaration),
    Namespace(Namespace),
    DecoratorDeclaration(DecoratorDeclaration),
    PipelineItemDeclaration(PipelineItemDeclaration),
}

impl Top {

    pub(crate) fn id(&self) -> usize {
        match self {
            Top::Import(i) => i.id(),
            Top::Constant(c) => c.id(),
            Top::Enum(e) => e.id(),
            Top::Model(m) => m.id(),
            Top::Config(c) => c.id(),
            Top::ConfigDeclaration(c) => c.id(),
            Top::DataSet(d) => d.id(),
            Top::Middleware(m) => m.id(),
            Top::ActionGroup(a) => a.id(),
            Top::Interface(i) => i.id(),
            Top::Namespace(n) => n.id(),
            Top::DecoratorDeclaration(d) => d.id(),
            Top::PipelineItemDeclaration(p) => p.id(),
        }
    }

    pub(crate) fn as_import(&self) -> Option<&Import> {
        match self {
            Top::Import(i) => Some(i),
            _ => None
        }
    }

    pub(crate) fn is_import(&self) -> bool {
        self.as_import().is_some()
    }

    pub(crate) fn as_constant(&self) -> Option<&Constant> {
        match self {
            Top::Constant(c) => Some(c),
            _ => None,
        }
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.as_constant().is_some()
    }

    pub(crate) fn as_enum(&self) -> Option<&Enum> {
        match self {
            Top::Enum(i) => Some(i),
            _ => None
        }
    }

    pub(crate) fn is_enum(&self) -> bool {
        self.as_enum().is_some()
    }

    pub(crate) fn as_model(&self) -> Option<&Model> {
        match self {
            Top::Model(i) => Some(i),
            _ => None
        }
    }

    pub(crate) fn is_model(&self) -> bool {
        self.as_model().is_some()
    }

    pub(crate) fn as_config(&self) -> Option<&Config> {
        match self {
            Top::Config(c) => Some(c),
            _ => None
        }
    }

    pub(crate) fn is_config(&self) -> bool {
        self.as_config().is_some()
    }

    pub(crate) fn as_config_declaration(&self) -> Option<&ConfigDeclaration> {
        match self {
            Top::ConfigDeclaration(c) => Some(c),
            _ => None
        }
    }

    pub(crate) fn is_config_declaration(&self) -> bool {
        self.as_config_declaration().is_some()
    }


    pub(crate) fn as_data_set(&self) -> Option<&DataSet> {
        match self {
            Top::DataSet(d) => Some(d),
            _ => None,
        }
    }

    pub(crate) fn is_data_set(&self) -> bool {
        self.as_data_set().is_some()
    }

    pub(crate) fn as_middleware(&self) -> Option<&Middleware> {
        match self {
            Top::Middleware(m) => Some(m),
            _ => None,
        }
    }

    pub(crate) fn is_middleware(&self) -> bool {
        self.as_middleware().is_some()
    }

    pub(crate) fn as_action_group(&self) -> Option<&ActionGroupDeclaration> {
        match self {
            Top::ActionGroup(m) => Some(m),
            _ => None,
        }
    }

    pub(crate) fn is_action_group(&self) -> bool {
        self.as_action_group().is_some()
    }

    pub(crate) fn as_interface(&self) -> Option<&InterfaceDeclaration> {
        match self {
            Top::Interface(m) => Some(m),
            _ => None,
        }
    }

    pub(crate) fn is_interface(&self) -> bool {
        self.as_interface().is_some()
    }

    pub(crate) fn as_namespace(&self) -> Option<&Namespace> {
        match self {
            Top::Namespace(n) => Some(n),
            _ => None,
        }
    }

    pub(crate) fn is_namespace(&self) -> bool {
        self.as_namespace().is_some()
    }

    pub(crate) fn as_decorator_declaration(&self) -> Option<&DecoratorDeclaration> {
        match self {
            Top::DecoratorDeclaration(d) => Some(d),
            _ => None,
        }
    }

    pub(crate) fn is_decorator_declaration(&self) -> bool {
        self.as_decorator_declaration().is_some()
    }

    pub(crate) fn as_pipeline_item_declaration(&self) -> Option<&PipelineItemDeclaration> {
        match self {
            Top::PipelineItemDeclaration(p) => Some(p),
            _ => None,
        }
    }

    pub(crate) fn is_pipeline_item_declaration(&self) -> bool {
        self.as_pipeline_item_declaration().is_some()
    }
}
