use std::sync::Arc;

use crate::availability::Availability;
use crate::expr::{ExprInfo, ReferenceInfo, ReferenceType};
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::node::Node;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::r#type::reference::Reference;
use crate::r#type::Type;
use crate::resolver::resolve_config::resolve_config_references;
use crate::resolver::resolve_constant::resolve_constant_references;

use crate::resolver::resolver_context::ResolverContext;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_identifier_with_diagnostic_message<'a>(
    identifier: &Identifier,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    if let Some(result) = resolve_identifier(identifier, context, ReferenceSpace::Default, context.current_availability()) {
        result
    } else {
        context.insert_diagnostics_error(identifier.span, "undefined identifier");
        ExprInfo::undetermined()
    }
}

pub(super) fn resolve_identifier<'a>(
    identifier: &Identifier,
    context: &'a ResolverContext<'a>,
    reference_type: ReferenceSpace,
    availability: Availability,
) -> Option<ExprInfo> {
    resolve_identifier_with_filter(
        identifier,
        context,
        &top_filter_for_reference_type(reference_type),
        availability,
    )
}

pub(super) fn resolve_identifier_with_filter<'a>(
    identifier: &Identifier,
    context: &'a ResolverContext<'a>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<ExprInfo> {
    resolve_identifier_path_names_with_filter_to_expr_info(
        &vec![identifier.name()],
        context.schema,
        context.source(),
        &context.current_namespace().map_or(vec![], |n| n.str_path()),
        filter,
        availability,
        context,
    )
}

pub(super) fn resolve_identifier_path<'a>(
    identifier_path: &IdentifierPath,
    context: &'a ResolverContext<'a>,
    reference_type: ReferenceSpace,
    availability: Availability,
) -> Option<ExprInfo> {
    resolve_identifier_path_with_filter(
        identifier_path,
        context,
        &top_filter_for_reference_type(reference_type),
        availability,
    )
}

pub(super) fn resolve_identifier_path_with_filter<'a>(
    identifier_path: &IdentifierPath,
    context: &'a ResolverContext<'a>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<ExprInfo> {
    resolve_identifier_path_names_with_filter_to_expr_info(
        &identifier_path.names(),
        context.schema,
        context.source(),
        &context.current_namespace().map_or(vec![], |n| n.str_path()),
        filter,
        availability,
        context,
    )
}

pub(crate) fn resolve_identifier_path_names_with_filter_to_expr_info<'a>(
    identifier_path_names: &Vec<&str>,
    schema: &'a Schema,
    source: &'a Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
    resolver_context: &'a ResolverContext<'a>,
) -> Option<ExprInfo> {
    resolve_identifier_path_names_with_filter_to_top(
        identifier_path_names,
        schema,
        source,
        namespace_str_path,
        filter,
        availability,
    ).map(move |t| top_to_expr_info(t, Some(resolver_context)))
}

pub fn resolve_identifier_path_names_with_filter_to_top<'a>(
    identifier_path_names: &Vec<&str>,
    schema: &'a Schema,
    source: &'a Source,
    namespace_str_path: &Vec<&str>,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<&'a Node> {
    let mut used_sources = vec![];
    let reference = resolve_identifier_path_names_in_source_to_top(
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
            if let Some(reference) = resolve_identifier_path_names_in_source_to_top(
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

fn resolve_identifier_path_names_in_source_to_top<'a>(
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
            if let Some(top) = source.find_node_by_string_path(identifier_path_names, filter, availability) {
                return Some(top);
            }
        } else {
            if let Some(ns) = source.find_child_namespace_by_string_path(&ns_str_path_mut) {
                if let Some(top) = ns.find_node_by_string_path(identifier_path_names, filter, availability) {
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
            if let Some(found) = resolve_identifier_path_names_in_source_to_top(identifier_path_names, schema, filter, from_source, used_sources, &ns_str_path, availability) {
                return Some(found)
            }
        }
    }
    None
}

pub(crate) fn top_to_expr_info<'a>(top: &'a Node, resolver_context: Option<&'a ResolverContext<'a>>) -> ExprInfo {
    match top {
        Node::Import(_) => ExprInfo::undetermined(),
        Node::Config(c) => ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::Config,
                Reference::new(c.path.clone(), c.string_path.clone()),
                None)
            ),
        },
        Node::NamedExpression(n) => if n.value().is_resolved() {
            ExprInfo {
                r#type: n.value().resolved().r#type.clone(),
                value: n.value().resolved().value.clone(),
                reference_info: Some(ReferenceInfo::new(
                    ReferenceType::DictionaryField,
                    Reference::new(n.path.clone(), vec![]),
                    None
                ))
            }
        } else {
            if let Some(resolver_context) = resolver_context {
                if resolver_context.has_dependency(&n.value().path()) {
                    resolver_context.insert_diagnostics_error(n.key().span(), "circular reference detected");
                    ExprInfo {
                        r#type: Type::Undetermined,
                        value: None,
                        reference_info: Some(ReferenceInfo::new(
                            ReferenceType::DictionaryField,
                            Reference::new(n.path().clone(), vec![]),
                            None)
                        ),
                    }
                } else {
                    resolver_context.alter_state_and_restore(n.source_id(), &n.namespace_path, |ctx| {
                        if n.is_config_field {
                            let mut p = n.parent_path();
                            p.pop();
                            let config = ctx.schema.find_top_by_path(&p).unwrap().as_config().unwrap();
                            resolve_config_references(config, resolver_context);
                        }
                    });
                    if n.value().is_resolved() {
                        ExprInfo {
                            r#type: n.value().resolved().r#type.clone(),
                            value: n.value().resolved().value.clone(),
                            reference_info: Some(ReferenceInfo::new(
                                ReferenceType::DictionaryField,
                                Reference::new(n.path.clone(), vec![]),
                                None)
                            ),
                        }
                    } else {
                        ExprInfo {
                            r#type: Type::Undetermined,
                            value: None,
                            reference_info: Some(ReferenceInfo::new(
                                ReferenceType::DictionaryField,
                                Reference::new(n.path.clone(), vec![]),
                                None)
                            ),
                        }
                    }
                }
            } else {
                ExprInfo {
                    r#type: Type::Undetermined,
                    value: None,
                    reference_info: Some(ReferenceInfo::new(
                        ReferenceType::DictionaryField,
                        Reference::new(n.path.clone(), vec![]),
                        None)
                    ),
                }
            }
        }
        Node::ConstantDeclaration(c) => if c.is_resolved() {
            ExprInfo {
                r#type: c.resolved().r#type.clone(),
                value: c.resolved().value.clone(),
                reference_info: Some(ReferenceInfo::new(
                    ReferenceType::Constant,
                    Reference::new(c.path.clone(), c.string_path.clone()),
                    None)
                ),
            }
        } else {
            if let Some(resolver_context) = resolver_context {
                if resolver_context.has_dependency(c.path()) {
                    resolver_context.insert_diagnostics_error(c.identifier().span, "circular reference detected");
                    ExprInfo {
                        r#type: Type::Undetermined,
                        value: None,
                        reference_info: Some(ReferenceInfo::new(
                            ReferenceType::Constant,
                            Reference::new(c.path.clone(), c.string_path.clone()),
                            None)
                        ),
                    }
                } else {
                    resolver_context.alter_state_and_restore(c.source_id(), &c.namespace_path(), |ctx| {
                        resolve_constant_references(c, resolver_context);
                    });
                    ExprInfo {
                        r#type: c.resolved().r#type.clone(),
                        value: c.resolved().value.clone(),
                        reference_info: Some(ReferenceInfo::new(
                            ReferenceType::Constant,
                            Reference::new(c.path.clone(), c.string_path.clone()),
                            None)
                        ),
                    }
                }
            } else {
                ExprInfo {
                    r#type: Type::Undetermined,
                    value: None,
                    reference_info: Some(ReferenceInfo::new(
                        ReferenceType::Constant,
                        Reference::new(c.path.clone(), c.string_path.clone()),
                        None)
                    ),
                }
            }
        }
        Node::Enum(e) => ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::Enum,
                Reference::new(e.path.clone(), e.string_path.clone()),
                None)
            )
        },
        Node::Model(m) => ExprInfo {
            r#type: Type::ModelObject(Reference::new(m.path.clone(), m.string_path.clone())),
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::Model,
                Reference::new(m.path.clone(), m.string_path.clone()),
                None
            ))
        },
        Node::DataSet(d) => ExprInfo {
            r#type: Type::DataSet,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::DataSet,
                Reference::new(d.path.clone(), d.string_path.clone()),
                None
            ))
        },
        Node::MiddlewareDeclaration(m) => ExprInfo {
            r#type: Type::Middleware,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::Middleware,
                Reference::new(m.path.clone(), m.string_path.clone()),
                None
            ))
        },
        Node::InterfaceDeclaration(i) => ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::Interface,
                Reference::new(i.path.clone(), i.string_path.clone()),
                None
            ))
        },
        Node::Namespace(n) => ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::Namespace,
                Reference::new(n.path.clone(), n.string_path.clone()),
                None
            ))
        },
        Node::DecoratorDeclaration(d) => ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::DecoratorDeclaration,
                Reference::new(d.path.clone(), d.string_path.clone()),
                None
            ))
        },
        Node::PipelineItemDeclaration(p) => ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::PipelineItemDeclaration,
                Reference::new(p.path.clone(), p.string_path.clone()),
                None
            ))
        },
        Node::StructDeclaration(s) => ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::StructDeclaration,
                Reference::new(s.path.clone(), s.string_path.clone()),
                None
            ))
        },
        Node::Field(f) => ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference_info: Some(ReferenceInfo::new(
                if f.resolved().class.is_interface_field() { ReferenceType::InterfaceField } else { ReferenceType::ModelField },
                Reference::new(f.path.clone(), f.string_path.clone()),
                None
            ))
        },
        Node::EnumMember(e) => ExprInfo {
            r#type: Type::EnumVariant(Reference::new(e.parent_path(), e.parent_string_path())),
            value: None,
            reference_info: Some(ReferenceInfo::new(
                ReferenceType::EnumMember,
                Reference::new(e.path.clone(), e.string_path.clone()),
                None
            ))
        },
        _ => ExprInfo::undetermined()
    }
}
