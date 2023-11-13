use std::sync::Arc;
use crate::ast::node::Node;
use crate::availability::Availability;
use crate::value::TypeAndValue;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::r#type::reference::Reference;
use crate::r#type::Type;
use crate::traits::resolved::Resolve;

pub fn search_identifier_path_names_with_filter_to_type_and_value(
    identifier_path_names: &Vec<&str>,
    schema: &Schema,
    source: &Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<TypeAndValue> {
    search_identifier_path_names_with_filter_to_top(
        identifier_path_names,
        schema,
        source,
        namespace_str_path,
        filter,
        availability
    ).map(|t| top_to_reference_type_and_value(t))
}

pub fn search_identifier_path_names_with_filter_to_path(
    identifier_path_names: &Vec<&str>,
    schema: &Schema,
    source: &Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<Vec<usize>> {
    search_identifier_path_names_with_filter_to_top(
        identifier_path_names,
        schema,
        source,
        namespace_str_path,
        filter,
        availability
    ).map(|t| t.path().clone())
}

pub fn search_identifier_path_names_with_filter_to_top<'a>(
    identifier_path_names: &Vec<&str>,
    schema: &'a Schema,
    source: &'a Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<&'a Node> {
    let mut used_sources = vec![];
    let reference = search_identifier_path_names_in_source_to_top(
        identifier_path_names,
        schema,
        filter,
        source,
        &mut used_sources,
        namespace_str_path,
        availability,
    );
    if reference.is_none() {
        for builtin_source in schema.builtin_sources() {
            if let Some(reference) = search_identifier_path_names_in_source_to_top(
                &identifier_path_names,
                schema,
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

fn search_identifier_path_names_in_source_to_top<'a>(
    identifier_path_names: &Vec<&str>,
    schema: &'a Schema,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    source: &'a Source,
    used_sources: &mut Vec<usize>,
    ns_str_path: &Vec<&str>,
    availability: Availability,
) -> Option<&'a Node> {
    if used_sources.contains(&source.id) {
        return None;
    }
    used_sources.push(source.id);
    let mut ns_str_path_mut = ns_str_path.clone();
    loop {
        if ns_str_path_mut.is_empty() {
            if let Some(top) = source.find_top_by_string_path(identifier_path_names, filter, availability) {
                return Some(top);
            }
        } else {
            if let Some(ns) = source.find_child_namespace_by_string_path(&ns_str_path_mut) {
                if let Some(top) = ns.find_top_by_string_path(identifier_path_names, filter, availability) {
                    return Some(top);
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
            if let Some(found) = search_identifier_path_names_in_source_to_top(identifier_path_names, schema, filter, from_source, used_sources, &ns_str_path, availability) {
                return Some(found)
            }
        }
    }
    None
}

fn top_to_reference_type_and_value(top: &Node) -> TypeAndValue {
    TypeAndValue {
        r#type: match top {
            Top::Import(_) => Type::Undetermined,
            Top::Config(c) => Type::ConfigReference(Reference::new(c.path.clone(), c.string_path.clone())),
            Top::ConfigDeclaration(_) => Type::Undetermined,
            Top::Constant(c) => return c.resolved().expression_resolved.clone(),
            Top::Enum(e) => Type::EnumReference(Reference::new(e.path.clone(), e.string_path.clone())),
            Top::Model(m) => Type::ModelReference(Reference::new(m.path.clone(), m.string_path.clone())),
            Top::DataSet(d) => Type::DataSetReference(d.string_path.clone()),
            Top::Middleware(m) => Type::MiddlewareReference(Reference::new(m.path.clone(), m.string_path.clone())),
            Top::HandlerGroup(_) => Type::Undetermined,
            Top::Interface(i) => if i.generics_declaration.is_none() {
                Type::InterfaceReference(Reference::new(i.path.clone(), i.string_path.clone()), vec![])
            } else {
                Type::Undetermined
            },
            Top::Namespace(n) => Type::NamespaceReference(n.string_path.clone()),
            Top::DecoratorDeclaration(d) => Type::DecoratorReference(Reference::new(d.path.clone(), d.string_path.clone())),
            Top::PipelineItemDeclaration(p) => Type::PipelineItemReference(Reference::new(p.path.clone(), p.string_path.clone())),
            Top::StructDeclaration(s) => if s.generics_declaration.is_none() {
                Type::StructReference(Reference::new(s.path.clone(), s.string_path.clone()), vec![])
            } else {
                Type::Undetermined
            }
            Top::UseMiddlewareBlock(_) => Type::Undetermined,
        },
        value: None,
    }
}

