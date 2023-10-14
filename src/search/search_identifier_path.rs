use std::sync::Arc;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::top::Top;

pub(crate) fn search_identifier_path_in_source(
    schema: &Schema,
    source: &Source,
    ns_str_path: &Vec<&str>,
    identifier_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Top) -> bool>,
) -> Option<Vec<usize>> {
    let mut used_sources = vec![];
    let reference = search_identifier_path_in_source_inner(
        schema,
        source,
        identifier_path,
        filter,
        &mut used_sources,
        ns_str_path,
    );
    if reference.is_none() {
        for builtin_source in schema.builtin_sources() {
            if let Some(reference) = search_identifier_path_in_source_inner(
                schema,
                builtin_source,
                &identifier_path,
                filter,
                &mut used_sources,
                &vec!["std"],
            ) {
                return Some(reference);
            }
        }
    }
    reference
}

fn search_identifier_path_in_source_inner(
    schema: &Schema,
    source: &Source,
    identifier_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Top) -> bool>,
    used_sources: &mut Vec<usize>,
    ns_str_path: &Vec<&str>,
) -> Option<Vec<usize>> {
    if used_sources.contains(&source.id) {
        return None;
    }
    used_sources.push(source.id);
    let mut ns_str_path_mut = ns_str_path.clone();
    loop {
        if ns_str_path_mut.is_empty() {
            if let Some(top) = source.find_top_by_string_path(&identifier_path, filter) {
                return Some(top.path().clone());
            }
        } else {
            if let Some(ns) = source.find_child_namespace_by_string_path(&ns_str_path_mut) {
                if let Some(top) = ns.find_top_by_string_path(&identifier_path, filter) {
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
        if let Some(from_source) = schema.sources().iter().find(|source| {
            import.file_path.as_str() == source.file_path.as_str()
        }).map(|s| *s) {
            if let Some(found) = search_identifier_path_in_source_inner(
                schema,
                from_source,
                identifier_path,
                filter,
                used_sources,
                &ns_str_path
            ) {
                return Some(found)
            }
        }
    }
    None
}
