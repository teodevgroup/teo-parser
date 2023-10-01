use crate::ast::top::Top;
use crate::resolver::resolve_model::resolve_model;
use crate::resolver::resolve_namespace::{resolve_namespace_first, resolve_namespace_second, resolve_namespace_third};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_source_first<'a>(context: &'a ResolverContext<'a>) {
    for top in context.source().tops() {
        match top {
            Top::Import(import) => (), // resolve_import(import, context),
            Top::Constant(_) => (), // only resolve when used
            Top::Enum(r#enum) => (), //resolve_enum(r#enum, context),
            Top::Model(model) => resolve_model(model, context),
            Top::Config(config) => (), // resolve_config(config, context),
            Top::DataSet(_) => (), // do not resolve yet
            Top::Middleware(middleware) => (),
            Top::Interface(interface) => (),
            Top::Namespace(namespace) => resolve_namespace_first(namespace, context),
            Top::ConfigDeclaration(_) => {}
            Top::ActionGroup(_) => {}
            Top::DecoratorDeclaration(_) => {}
            Top::PipelineItemDeclaration(_) => {}
        }
    }
}

pub(super) fn resolve_source_second<'a>(context: &'a ResolverContext<'a>) {
    for top in context.source().tops() {
        match top {
            Top::DataSet(data_set) => (), // resolve_data_set(data_set, context),
            Top::Namespace(namespace) => resolve_namespace_second(namespace, context),
            _ => ()
        }
    }
}

pub(super) fn resolve_source_third<'a>(context: &'a ResolverContext<'a>) {
    for top in context.source().tops() {
        match top {
            Top::DataSet(data_set) => (), //resolve_data_set_records(data_set, context),
            Top::Namespace(namespace) => resolve_namespace_third(namespace, context),
            _ => ()
        }
    }
}