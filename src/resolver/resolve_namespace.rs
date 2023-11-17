use crate::ast::namespace::Namespace;
use crate::ast::node::Node;
use crate::resolver::resolve_handler_group::resolve_handler_group_types;
use crate::resolver::resolve_config::resolve_config;
use crate::resolver::resolve_config_declaration::resolve_config_declaration;
use crate::resolver::resolve_constant::resolve_constant;
use crate::resolver::resolve_data_set::{resolve_data_set, resolve_data_set_records};
use crate::resolver::resolve_decorator_declaration::resolve_decorator_declaration;
use crate::resolver::resolve_enum::resolve_enum;
use crate::resolver::resolve_interface::resolve_interface_declaration;
use crate::resolver::resolve_middleware::resolve_middleware;
use crate::resolver::resolve_model::{resolve_model_decorators, resolve_model_info};
use crate::resolver::resolve_pipeline_item_declaration::resolve_pipeline_item_declaration;
use crate::resolver::resolve_struct_declaration::resolve_struct_declaration;
use crate::resolver::resolve_use_middlewares_block::resolve_use_middlewares_block;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::node_trait::NodeTrait;

pub(super) fn resolve_namespace_first<'a>(namespace: &'a Namespace, context: &'a ResolverContext<'a>) {
    context.push_namespace(namespace);
    for top in namespace.children.values() {
        match top {
            Node::Import(_) => (), // no imports in namespace
            Node::Constant(constant) => resolve_constant(constant, context),
            Node::Enum(r#enum) => resolve_enum(r#enum, context),
            Node::Model(model) => resolve_model_info(model, context),
            Node::Config(config) => resolve_config(config, context),
            Node::DataSet(_) => (), // don't resolve the first time
            Node::MiddlewareDeclaration(middleware) => resolve_middleware(middleware, context),
            Node::InterfaceDeclaration(interface) => resolve_interface_declaration(interface, context),
            Node::Namespace(namespace) => resolve_namespace_first(namespace, context),
            Node::HandlerGroupDeclaration(handler_group) => resolve_handler_group_types(handler_group, context),
            Node::ConfigDeclaration(config_declaration) => resolve_config_declaration(config_declaration, context),
            Node::DecoratorDeclaration(d) => resolve_decorator_declaration(d, context),
            Node::PipelineItemDeclaration(p) => resolve_pipeline_item_declaration(p, context),
            Node::StructDeclaration(s) => resolve_struct_declaration(s, context),
            Node::UseMiddlewaresBlock(_u) => (),
            _ => (),
        }
    }
    context.pop_namespace();
}

pub(super) fn resolve_namespace_second<'a>(namespace: &'a Namespace, context: &'a ResolverContext<'a>) {
    context.push_namespace(namespace);
    for top in namespace.children.values() {
        match top {
            Node::DataSet(data_set) => resolve_data_set(data_set, context),
            Node::Namespace(namespace) => resolve_namespace_second(namespace, context),
            Node::Model(model) => resolve_model_decorators(model, context),
            Node::UseMiddlewaresBlock(u) => resolve_use_middlewares_block(u, context),
            _ => ()
        }
    }
    context.pop_namespace();
}

pub(super) fn resolve_namespace_third<'a>(namespace: &'a Namespace, context: &'a ResolverContext<'a>) {
    context.push_namespace(namespace);
    for top in namespace.children.values() {
        match top {
            Node::DataSet(data_set) => resolve_data_set_records(data_set, context),
            Node::Namespace(namespace) => resolve_namespace_third(namespace, context),
            _ => ()
        }
    }
    context.pop_namespace();
}