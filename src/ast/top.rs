use crate::ast::availability::Availability;
use crate::ast::handler::HandlerGroupDeclaration;
use crate::ast::config::Config;
use crate::ast::config_declaration::ConfigDeclaration;
use crate::ast::constant::Constant;
use crate::ast::data_set::DataSet;
use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::identifiable::Identifiable;
use crate::ast::identifier::Identifier;
use crate::ast::import::Import;
use crate::ast::interface::InterfaceDeclaration;
use crate::ast::middleware::MiddlewareDeclaration;
use crate::ast::model::Model;
use crate::ast::namespace::Namespace;
use crate::ast::pipeline_item_declaration::PipelineItemDeclaration;
use crate::ast::r#enum::Enum;
use crate::ast::span::Span;
use crate::ast::struct_declaration::StructDeclaration;
use crate::ast::use_middlewares::UseMiddlewaresBlock;

#[derive(Debug)]
pub enum Top {
    Import(Import),
    Config(Config),
    ConfigDeclaration(ConfigDeclaration),
    Constant(Constant),
    Enum(Enum),
    Model(Model),
    DataSet(DataSet),
    Middleware(MiddlewareDeclaration),
    HandlerGroup(HandlerGroupDeclaration),
    Interface(InterfaceDeclaration),
    Namespace(Namespace),
    DecoratorDeclaration(DecoratorDeclaration),
    PipelineItemDeclaration(PipelineItemDeclaration),
    StructDeclaration(StructDeclaration),
    UseMiddlewareBlock(UseMiddlewaresBlock),
}

impl Top {

    pub fn source_id(&self) -> usize {
        match self {
            Top::Import(i) => i.source_id(),
            Top::Constant(c) => c.source_id(),
            Top::Enum(e) => e.source_id(),
            Top::Model(m) => m.source_id(),
            Top::Config(c) => c.source_id(),
            Top::ConfigDeclaration(c) => c.source_id(),
            Top::DataSet(d) => d.source_id(),
            Top::Middleware(m) => m.source_id(),
            Top::HandlerGroup(a) => a.source_id(),
            Top::Interface(i) => i.source_id(),
            Top::Namespace(n) => n.source_id(),
            Top::DecoratorDeclaration(d) => d.source_id(),
            Top::PipelineItemDeclaration(p) => p.source_id(),
            Top::StructDeclaration(s) => s.source_id(),
            Top::UseMiddlewareBlock(u) => u.source_id(),
        }
    }

    pub fn id(&self) -> usize {
        match self {
            Top::Import(i) => i.id(),
            Top::Constant(c) => c.id(),
            Top::Enum(e) => e.id(),
            Top::Model(m) => m.id(),
            Top::Config(c) => c.id(),
            Top::ConfigDeclaration(c) => c.id(),
            Top::DataSet(d) => d.id(),
            Top::Middleware(m) => m.id(),
            Top::HandlerGroup(a) => a.id(),
            Top::Interface(i) => i.id(),
            Top::Namespace(n) => n.id(),
            Top::DecoratorDeclaration(d) => d.id(),
            Top::PipelineItemDeclaration(p) => p.id(),
            Top::StructDeclaration(s) => s.id(),
            Top::UseMiddlewareBlock(u) => u.id(),
        }
    }

    pub fn identifier_span(&self) -> Option<Span> {
        match self {
            Top::Import(i) => None,
            Top::Constant(c) => Some(c.identifier.span),
            Top::Enum(e) => Some(e.identifier.span),
            Top::Model(m) => Some(m.identifier.span),
            Top::Config(c) => Some(c.identifier.as_ref().map_or(c.keyword.span, |i| i.span)),
            Top::ConfigDeclaration(c) => Some(c.identifier.span),
            Top::DataSet(d) => Some(d.identifier.span),
            Top::Middleware(m) => Some(m.identifier.span),
            Top::HandlerGroup(a) => Some(a.identifier.span),
            Top::Interface(i) => Some(i.identifier.span),
            Top::Namespace(n) => Some(n.identifier.span),
            Top::DecoratorDeclaration(d) => Some(d.identifier.span),
            Top::PipelineItemDeclaration(p) => Some(p.identifier.span),
            Top::StructDeclaration(s) => Some(s.identifier.span),
            Top::UseMiddlewareBlock(u) => None,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Top::Import(i) => None,
            Top::Constant(c) => Some(c.identifier.name()),
            Top::Enum(e) => Some(e.identifier.name()),
            Top::Model(m) => Some(m.identifier.name()),
            Top::Config(c) => Some(c.name()),
            Top::ConfigDeclaration(c) => Some(c.identifier.name()),
            Top::DataSet(d) => Some(d.identifier.name()),
            Top::Middleware(m) => Some(m.identifier.name()),
            Top::HandlerGroup(a) => Some(a.identifier.name()),
            Top::Interface(i) => Some(i.identifier.name()),
            Top::Namespace(n) => Some(n.identifier.name()),
            Top::DecoratorDeclaration(d) => Some(d.identifier.name()),
            Top::PipelineItemDeclaration(p) => Some(p.identifier.name()),
            Top::StructDeclaration(s) => Some(s.identifier.name()),
            Top::UseMiddlewareBlock(u) => None,
        }
    }

    pub fn path(&self) -> &Vec<usize> {
        match self {
            Top::Import(i) => &i.path,
            Top::Constant(c) => &c.path,
            Top::Enum(e) => &e.path,
            Top::Model(m) => &m.path,
            Top::Config(c) => &c.path,
            Top::ConfigDeclaration(c) => &c.path,
            Top::DataSet(d) => &d.path,
            Top::Middleware(m) => &m.path,
            Top::HandlerGroup(a) => &a.path,
            Top::Interface(i) => &i.path,
            Top::Namespace(n) => &n.path,
            Top::DecoratorDeclaration(d) => &d.path,
            Top::PipelineItemDeclaration(p) => &p.path,
            Top::StructDeclaration(s) => &s.path,
            Top::UseMiddlewareBlock(u) => &u.path,
        }
    }

    pub fn str_path(&self) -> Option<Vec<&str>> {
        match self {
            Top::Import(i) => None,
            Top::Constant(c) => Some(c.str_path()),
            Top::Enum(e) => Some(e.str_path()),
            Top::Model(m) => Some(m.str_path()),
            Top::Config(c) => Some(c.str_path()),
            Top::ConfigDeclaration(c) => Some(c.str_path()),
            Top::DataSet(d) => Some(d.str_path()),
            Top::Middleware(m) => Some(m.str_path()),
            Top::HandlerGroup(h) => Some(h.str_path()),
            Top::Interface(i) => Some(i.str_path()),
            Top::Namespace(n) => Some(n.str_path()),
            Top::DecoratorDeclaration(d) => Some(d.str_path()),
            Top::PipelineItemDeclaration(p) => Some(p.str_path()),
            Top::StructDeclaration(s) => Some(s.str_path()),
            Top::UseMiddlewareBlock(u) => None,
        }
    }

    pub fn span(&self) -> Span {
        match self {
            Top::Import(i) => i.span,
            Top::Constant(c) => c.span,
            Top::Enum(e) => e.span,
            Top::Model(m) => m.span,
            Top::Config(c) => c.span,
            Top::ConfigDeclaration(c) => c.span,
            Top::DataSet(d) => d.span,
            Top::Middleware(m) => m.span,
            Top::HandlerGroup(a) => a.span,
            Top::Interface(i) => i.span,
            Top::Namespace(n) => n.span,
            Top::DecoratorDeclaration(d) => d.span,
            Top::PipelineItemDeclaration(p) => p.span,
            Top::StructDeclaration(s) => s.span,
            Top::UseMiddlewareBlock(u) => u.span,
        }
    }

    pub fn available_test(&self, availability: Availability) -> bool {
        match self {
            Top::Import(_) => true,
            Top::Config(_) => true,
            Top::ConfigDeclaration(_) => true,
            Top::Constant(t) => t.define_availability.contains(availability),
            Top::Enum(t) => t.define_availability.contains(availability),
            Top::Model(t) => t.define_availability.contains(availability),
            Top::DataSet(t) => t.define_availability.contains(availability),
            Top::Middleware(_) => true,
            Top::HandlerGroup(t) => true,
            Top::Interface(t) => t.define_availability.contains(availability),
            Top::Namespace(_) => true,
            Top::DecoratorDeclaration(t) => t.define_availability.contains(availability),
            Top::PipelineItemDeclaration(t) => t.define_availability.contains(availability),
            Top::StructDeclaration(t) => t.define_availability.contains(availability),
            Top::UseMiddlewareBlock(u) => true,
        }
    }

    pub fn as_import(&self) -> Option<&Import> {
        match self {
            Top::Import(i) => Some(i),
            _ => None
        }
    }

    pub fn is_import(&self) -> bool {
        self.as_import().is_some()
    }

    pub fn as_constant(&self) -> Option<&Constant> {
        match self {
            Top::Constant(c) => Some(c),
            _ => None,
        }
    }

    pub fn is_constant(&self) -> bool {
        self.as_constant().is_some()
    }

    pub fn as_enum(&self) -> Option<&Enum> {
        match self {
            Top::Enum(i) => Some(i),
            _ => None
        }
    }

    pub fn is_enum(&self) -> bool {
        self.as_enum().is_some()
    }

    pub fn as_model(&self) -> Option<&Model> {
        match self {
            Top::Model(i) => Some(i),
            _ => None
        }
    }

    pub fn is_model(&self) -> bool {
        self.as_model().is_some()
    }

    pub fn as_config(&self) -> Option<&Config> {
        match self {
            Top::Config(c) => Some(c),
            _ => None
        }
    }

    pub fn is_config(&self) -> bool {
        self.as_config().is_some()
    }

    pub fn as_config_declaration(&self) -> Option<&ConfigDeclaration> {
        match self {
            Top::ConfigDeclaration(c) => Some(c),
            _ => None
        }
    }

    pub fn is_config_declaration(&self) -> bool {
        self.as_config_declaration().is_some()
    }


    pub fn as_data_set(&self) -> Option<&DataSet> {
        match self {
            Top::DataSet(d) => Some(d),
            _ => None,
        }
    }

    pub fn is_data_set(&self) -> bool {
        self.as_data_set().is_some()
    }

    pub fn as_middleware_declaration(&self) -> Option<&MiddlewareDeclaration> {
        match self {
            Top::Middleware(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_middleware_declaration(&self) -> bool {
        self.as_middleware_declaration().is_some()
    }

    pub fn as_handler_group_declaration(&self) -> Option<&HandlerGroupDeclaration> {
        match self {
            Top::HandlerGroup(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_handler_group_declaration(&self) -> bool {
        self.as_handler_group_declaration().is_some()
    }

    pub fn as_interface_declaration(&self) -> Option<&InterfaceDeclaration> {
        match self {
            Top::Interface(m) => Some(m),
            _ => None,
        }
    }

    pub fn is_interface_declaration(&self) -> bool {
        self.as_interface_declaration().is_some()
    }

    pub fn as_namespace(&self) -> Option<&Namespace> {
        match self {
            Top::Namespace(n) => Some(n),
            _ => None,
        }
    }

    pub fn is_namespace(&self) -> bool {
        self.as_namespace().is_some()
    }

    pub fn as_decorator_declaration(&self) -> Option<&DecoratorDeclaration> {
        match self {
            Top::DecoratorDeclaration(d) => Some(d),
            _ => None,
        }
    }

    pub fn is_decorator_declaration(&self) -> bool {
        self.as_decorator_declaration().is_some()
    }

    pub fn as_pipeline_item_declaration(&self) -> Option<&PipelineItemDeclaration> {
        match self {
            Top::PipelineItemDeclaration(p) => Some(p),
            _ => None,
        }
    }

    pub fn is_pipeline_item_declaration(&self) -> bool {
        self.as_pipeline_item_declaration().is_some()
    }

    pub fn as_struct_declaration(&self) -> Option<&StructDeclaration> {
        match self {
            Top::StructDeclaration(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_struct_declaration(&self) -> bool {
        self.as_struct_declaration().is_some()
    }

    pub fn as_use_middlewares_block(&self) -> Option<&UseMiddlewaresBlock> {
        match self {
            Top::UseMiddlewareBlock(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_use_middlewares_block(&self) -> bool {
        self.as_use_middlewares_block().is_some()
    }
}
