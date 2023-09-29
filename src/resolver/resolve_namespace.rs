use crate::ast::namespace::Namespace;
use crate::ast::top::Top;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_namespace_first(namespace: &Namespace, context: &mut ResolverContext) {
    for top in namespace.tops() {
        match top {
            Top::Import(_) => (), // no imports in namespace
            Top::Constant(constant) => resolve_constant(constant, context),
            Top::Enum(r#enum) => resolve_enum(r#enum, context),
            Top::Model(model) => resolve_model(model, context),
            Top::Config(config) => resolve_config(config, context),
            Top::DataSet(_) => (), // don't resolve the first time
            Top::Middleware(_) => (),
            Top::Interface(_) => (),
            Top::Namespace(namespace) => resolve_namespace_first(namespace, context),
            Top::ActionGroup(_) => (),
        }
    }
}

pub(super) fn resolve_namespace_second(namespace: &Namespace, context: &mut ResolverContext) {
    for top in namespace.tops() {
        match top {
            Top::DataSet(data_set) => resolve_data_set(data_set, context),
            Top::Namespace(namespace) => resolve_namespace_second(namespace, context),
            _ => ()
        }
    }
}

pub(super) fn resolve_namespace_third(namespace: &Namespace, context: &mut ResolverContext) {
    for top in namespace.tops() {
        match top {
            Top::DataSet(data_set) => resolve_data_set_records(data_set, context),
            Top::Namespace(namespace) => resolve_namespace_third(namespace, context),
            _ => ()
        }
    }
}