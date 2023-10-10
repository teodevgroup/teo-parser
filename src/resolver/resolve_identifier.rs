use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::reference::{Reference, ReferenceType};
use crate::ast::source::Source;
use crate::ast::top::Top;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_constant::resolve_constant;
use crate::resolver::resolver_context::ResolverContext;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_identifier_into_type(
    identifier: &Identifier,
    context: &ResolverContext,
) -> Type {
    if let Some(reference) = resolve_identifier(identifier, context, ReferenceType::Default) {
        // maybe add error here
        track_path_upwards_into_type(&reference.path, context)
    } else {
        context.insert_diagnostics_error(identifier.span, "undefined identifier");
        Type::Undetermined
    }
}

fn track_path_upwards_into_type<'a>(path: &Vec<usize>, context: &'a ResolverContext<'a>) -> Type {
    let top = context.schema.find_top_by_path(path).unwrap();
    match top {
        Top::Config(c) => Type::Undetermined,
        Top::Constant(c) => {
            if !c.is_resolved() {
                resolve_constant(c, context);
            }
            c.resolved().r#type.clone()
        }
        Top::Enum(e) => Type::Undetermined,
        Top::Model(m) => Type::Model,
        Top::Interface(i) => Type::Undetermined,
        Top::Namespace(n) => Type::Undetermined,
        _ => unreachable!(),
    }
}

pub(super) fn resolve_identifier(
    identifier: &Identifier,
    context: &ResolverContext,
    reference_type: ReferenceType,
) -> Option<Reference> {
    resolve_identifier_path(
        &IdentifierPath::from_identifier(identifier.clone()),
        context,
        reference_type,
    )
}

pub(super) fn resolve_identifier_path(
    identifier_path: &IdentifierPath,
    context: &ResolverContext,
    reference_type: ReferenceType,
) -> Option<Reference> {
    let mut used_sources = vec![];
    let ns_str_path = context.current_namespace().map_or(vec![], |n| n.str_path());
    let reference = resolve_identifier_path_in_source(
        identifier_path,
        context,
        reference_type,
        context.source(),
        &mut used_sources,
        &ns_str_path
    );
    if reference.is_none() {
        for builtin_source in context.schema.builtin_sources() {
            if let Some(reference) = resolve_identifier_path_in_source(
                &identifier_path,
                context,
                reference_type,
                builtin_source,
                &mut used_sources,
                &vec!["std"],
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
    reference_type: ReferenceType,
    source: &Source,
    used_sources: &mut Vec<usize>,
    ns_str_path: &Vec<&str>,
) -> Option<Reference> {
    if used_sources.contains(&source.id) {
        return None;
    }
    used_sources.push(source.id);
    let mut ns_str_path_mut = ns_str_path.clone();
    loop {
        if ns_str_path_mut.is_empty() {
            if let Some(top) = source.find_top_by_string_path(&identifier_path.names(), &top_filter_for_reference_type(reference_type)) {
                return Some(Reference {
                    path: top.path().clone(),
                    r#type: reference_type,
                });
            }
        } else {
            if let Some(ns) = source.find_child_namespace_by_string_path(&ns_str_path_mut) {
                if let Some(top) = ns.find_top_by_string_path(&identifier_path.names(), &top_filter_for_reference_type(reference_type)) {
                    return Some(Reference {
                        path: top.path().clone(),
                        r#type: reference_type,
                    });
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
            if let Some(found) = resolve_identifier_path_in_source(identifier_path, context, reference_type, from_source, used_sources, &ns_str_path) {
                return Some(found)
            }
        }
    }
    None
}
