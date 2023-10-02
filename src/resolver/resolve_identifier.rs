use std::sync::Arc;
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::reference::{Reference, ReferenceType};
use crate::ast::source::Source;
use crate::ast::top::Top;
use crate::resolver::resolver_context::ResolverContext;

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
        let from_source = context.schema.sources().iter().find(|source| {
            import.file_path.as_str() == source.file_path.as_str()
        }).map(|s| *s).unwrap();
        if let Some(found) = resolve_identifier_path_in_source(identifier_path, context, reference_type, from_source, used_sources, &ns_str_path) {
            return Some(found)
        }
    }
    None
}

fn top_filter_for_reference_type(reference_type: ReferenceType) -> Arc<dyn Fn(&Top) -> bool> {
    match reference_type {
        ReferenceType::EnumDecorator |
        ReferenceType::EnumMemberDecorator |
        ReferenceType::ModelDecorator |
        ReferenceType::ModelFieldDecorator |
        ReferenceType::ModelRelationDecorator |
        ReferenceType::ModelPropertyDecorator |
        ReferenceType::InterfaceDecorator |
        ReferenceType::InterfaceFieldDecorator => Arc::new(move |top: &Top| {
            top.as_decorator_declaration().map_or(false, |d| d.decorator_class == reference_type)
        }),
        ReferenceType::PipelineItem => Arc::new(|top: &Top| {
            top.as_pipeline_item_declaration().is_some()
        }),
        ReferenceType::Default => Arc::new(|top: &Top| {
            top.is_enum() || top.is_model() || top.is_interface() || top.is_config() || top.is_constant()
        }),
    }
}