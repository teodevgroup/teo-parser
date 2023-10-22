use std::sync::Arc;
use crate::ast::availability::Availability;
use crate::ast::expression::ExpressionResolved;
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::reference::ReferenceType;
use crate::ast::source::Source;
use crate::ast::top::Top;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_constant::resolve_constant;
use crate::resolver::resolver_context::ResolverContext;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_identifier_into_type<'a>(
    identifier: &Identifier,
    context: &'a ResolverContext<'a>,
) -> ExpressionResolved {
    if let Some(reference) = resolve_identifier(identifier, context, ReferenceType::Default, context.current_availability()) {
        // maybe add error here
        track_path_upwards_into_type(&reference, context)
    } else {
        context.insert_diagnostics_error(identifier.span, "undefined identifier");
        ExpressionResolved::undetermined()
    }
}

fn track_path_upwards_into_type<'a>(path: &Vec<usize>, context: &'a ResolverContext<'a>) -> ExpressionResolved {
    let top = context.schema.find_top_by_path(path).unwrap();
    match top {
        Top::Config(c) => ExpressionResolved::undetermined(),
        Top::Constant(c) => {
            if !c.is_resolved() {
                resolve_constant(c, context);
            }
            c.resolved().expression_resolved.clone()
        }
        Top::Enum(e) => ExpressionResolved::undetermined(),
        Top::Model(m) => ExpressionResolved {
            r#type: Type::Model,
            value: Some(m.string_path.into()),
        },
        Top::DataSet(d) => ExpressionResolved {
            r#type: Type::DataSet,
            value: Some(d.string_path.into())
        },
        Top::Interface(i) => ExpressionResolved::undetermined(),
        Top::Namespace(n) => ExpressionResolved::undetermined(),
        _ => unreachable!(),
    }
}

pub(super) fn resolve_identifier(
    identifier: &Identifier,
    context: &ResolverContext,
    reference_type: ReferenceType,
    availability: Availability,
) -> Option<Vec<usize>> {
    resolve_identifier_path(
        &IdentifierPath::from_identifier(identifier.clone()),
        context,
        reference_type,
        availability,
    )
}

pub(super) fn resolve_identifier_with_filter(
    identifier: &Identifier,
    context: &ResolverContext,
    filter: &Arc<dyn Fn(&Top) -> bool>,
    availability: Availability,
) -> Option<Vec<usize>> {
    resolve_identifier_path_with_filter(
        &IdentifierPath::from_identifier(identifier.clone()),
        context,
        filter,
        availability,
    )
}

pub(super) fn resolve_identifier_path(
    identifier_path: &IdentifierPath,
    context: &ResolverContext,
    reference_type: ReferenceType,
    availability: Availability,
) -> Option<Vec<usize>> {
    resolve_identifier_path_with_filter(
        identifier_path,
        context,
        &top_filter_for_reference_type(reference_type),
        availability,
    )
}

pub(super) fn resolve_identifier_path_with_filter(
    identifier_path: &IdentifierPath,
    context: &ResolverContext,
    filter: &Arc<dyn Fn(&Top) -> bool>,
    availability: Availability,
) -> Option<Vec<usize>> {
    let mut used_sources = vec![];
    let ns_str_path = context.current_namespace().map_or(vec![], |n| n.str_path());
    let reference = resolve_identifier_path_in_source(
        identifier_path,
        context,
        filter,
        context.source(),
        &mut used_sources,
        &ns_str_path,
        availability,
    );
    if reference.is_none() {
        for builtin_source in context.schema.builtin_sources() {
            if let Some(reference) = resolve_identifier_path_in_source(
                &identifier_path,
                context,
                filter,
                builtin_source,
                &mut used_sources,
                &vec!["std"],
                availability,
            ) {
                return Some(reference);
            }
        }
    }
    reference
}

fn resolve_identifier_path_in_source(
    identifier_path: &IdentifierPath,
    context: &ResolverContext,
    filter: &Arc<dyn Fn(&Top) -> bool>,
    source: &Source,
    used_sources: &mut Vec<usize>,
    ns_str_path: &Vec<&str>,
    availability: Availability,
) -> Option<Vec<usize>> {
    if used_sources.contains(&source.id) {
        return None;
    }
    used_sources.push(source.id);
    let mut ns_str_path_mut = ns_str_path.clone();
    loop {
        if ns_str_path_mut.is_empty() {
            if let Some(top) = source.find_top_by_string_path(&identifier_path.names(), filter, availability) {
                return Some(top.path().clone());
            }
        } else {
            if let Some(ns) = source.find_child_namespace_by_string_path(&ns_str_path_mut) {
                if let Some(top) = ns.find_top_by_string_path(&identifier_path.names(), filter, availability) {
                    return Some(top.path().clone());
                }
            }
        }
        if ns_str_path_mut.len() > 0 {
            ns_str_path_mut.pop();
        } else {
            break
        }
    }
    for import in source.imports() {
        // find with imports
        if let Some(from_source) = context.schema.sources().iter().find(|source| {
            import.file_path.as_str() == source.file_path.as_str()
        }).map(|s| *s) {
            if let Some(found) = resolve_identifier_path_in_source(identifier_path, context, filter, from_source, used_sources, &ns_str_path, availability) {
                return Some(found)
            }
        }
    }
    None
}
