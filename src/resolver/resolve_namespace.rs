use crate::ast::namespace::Namespace;
use crate::ast::node::Node;
use crate::resolver::resolve_handler_group::{resolve_handler_group_decorators, resolve_handler_group_references};
use crate::resolver::resolve_config::resolve_config_references;
use crate::resolver::resolve_config_declaration::resolve_config_declaration_types;
use crate::resolver::resolve_constant::resolve_constant_references;
use crate::resolver::resolve_data_set::{resolve_data_set_references, resolve_data_set_records};
use crate::resolver::resolve_decorator_declaration::resolve_decorator_declaration_references;
use crate::resolver::resolve_enum::resolve_enum_types;
use crate::resolver::resolve_interface::resolve_interface_declaration_types;
use crate::resolver::resolve_middleware::resolve_middleware_references;
use crate::resolver::resolve_model::{resolve_model_decorators, resolve_model_types};
use crate::resolver::resolve_pipeline_item_declaration::resolve_pipeline_item_declaration_references;
use crate::resolver::resolve_struct_declaration::resolve_struct_declaration_types;
use crate::resolver::resolve_use_middlewares_block::resolve_use_middlewares_block;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_namespace_types<'a>(namespace: &'a Namespace, context: &'a ResolverContext<'a>) {
    context.push_namespace(namespace);
    for node in namespace.children.values() {
        match node {
            Node::Enum(r#enum) => resolve_enum_types(r#enum, context),
            Node::Model(model) => resolve_model_types(model, context),
            Node::InterfaceDeclaration(interface) => resolve_interface_declaration_types(interface, context),
            Node::Namespace(namespace) => resolve_namespace_types(namespace, context),
            Node::ConfigDeclaration(config_declaration) => resolve_config_declaration_types(config_declaration, context),
            Node::StructDeclaration(s) => resolve_struct_declaration_types(s, context),
            _ => (),
        }
    }
    context.pop_namespace();
}

pub(super) fn resolve_namespace_references_first<'a>(namespace: &'a Namespace, context: &'a ResolverContext<'a>) {
    context.push_namespace(namespace);
    for node in namespace.children.values() {
        match node {
            Node::Constant(constant) => resolve_constant_references(constant, context),
            Node::Config(config) => resolve_config_references(config, context),
            Node::MiddlewareDeclaration(middleware) => resolve_middleware_references(middleware, context),
            Node::Namespace(namespace) => resolve_namespace_references_first(namespace, context),
            Node::Model(model) => resolve_model_references(model, context),
            Node::HandlerGroupDeclaration(handler_group) => resolve_handler_group_references(handler_group, context),
            Node::DecoratorDeclaration(d) => resolve_decorator_declaration_references(d, context),
            Node::PipelineItemDeclaration(p) => resolve_pipeline_item_declaration_references(p, context),
            Node::DataSet(data_set) => resolve_data_set_references(data_set, context),
            _ => (),
        }
    }
    context.pop_namespace();
}

pub(super) fn resolve_namespace_references_second<'a>(namespace: &'a Namespace, context: &'a ResolverContext<'a>) {
    context.push_namespace(namespace);
    for node in namespace.children.values() {
        match node {
            Node::Constant(constant) => resolve_constant_references(constant, context),
            Node::Config(config) => resolve_config_references(config, context),
            Node::Namespace(namespace) => resolve_namespace_references_second(namespace, context),
            _ => (),
        }
    }
    context.pop_namespace();
}

pub(super) fn resolve_namespace_references_check<'a>(namespace: &'a Namespace, context: &'a ResolverContext<'a>) {
    context.push_namespace(namespace);
    for node in namespace.children.values() {
        match node {
            Node::Constant(constant) => resolve_constant_references_check(constant, context),
            Node::Config(config) => resolve_config_references_check(config, context),
            Node::Namespace(namespace) => resolve_namespace_references_check(namespace, context),
            _ => (),
        }
    }
    context.pop_namespace();
}

pub(super) fn resolve_namespace_consumers<'a>(namespace: &'a Namespace, context: &'a ResolverContext<'a>) {
    context.push_namespace(namespace);
    for node in namespace.children.values() {
        match node {
            Node::DataSet(data_set) => resolve_data_set_records(data_set, context),
            Node::Namespace(namespace) => resolve_namespace_consumers(namespace, context),
            Node::Model(model) => resolve_model_decorators(model, context),
            Node::HandlerGroupDeclaration(handler_group) => resolve_handler_group_decorators(handler_group, context),
            Node::UseMiddlewaresBlock(u) => resolve_use_middlewares_block(u, context),
            _ => (),
        }
    }
    context.pop_namespace();
}
