use std::sync::Arc;
use teo_teon::Value;
use crate::ast::availability::Availability;
use crate::ast::expression::TypeAndValue;
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::reference::ReferenceType;
use crate::ast::top::Top;
use crate::r#type::r#type::Type;
use crate::resolver::resolver_context::ResolverContext;
use crate::search::search_identifier_path::search_identifier_path_names_with_filter;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_identifier_with_value<'a>(
    identifier: &Identifier,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    if let Some(reference) = resolve_identifier(identifier, context, ReferenceType::Default, context.current_availability()) {
        // maybe add error here
        track_path_upwards_into_type(reference.path(), context)
    } else {
        context.insert_diagnostics_error(identifier.span, "undefined identifier");
        TypeAndValue::undetermined()
    }
}

fn track_path_upwards_into_type<'a>(path: &Vec<usize>, context: &'a ResolverContext<'a>) -> TypeAndValue {
    let top = context.schema.find_top_by_path(path).unwrap();
    match top {
        Top::Config(c) => TypeAndValue::undetermined(),
        Top::Constant(c) => {
            c.resolved().expression_resolved.clone()
        }
        Top::Enum(e) => TypeAndValue::undetermined(),
        Top::Model(m) => TypeAndValue {
            r#type: Type::Model,
            value: Some(Value::from(m.string_path.clone())),
        },
        Top::DataSet(d) => TypeAndValue {
            r#type: Type::DataSet,
            value: Some(Value::from(d.string_path.clone()))
        },
        Top::Interface(i) => TypeAndValue::undetermined(),
        Top::Namespace(n) => TypeAndValue::undetermined(),
        _ => unreachable!(),
    }
}

pub(super) fn resolve_identifier(
    identifier: &Identifier,
    context: &ResolverContext,
    reference_type: ReferenceType,
    availability: Availability,
) -> Option<Type> {
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
) -> Option<Type> {
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
) -> Option<Type> {
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
) -> Option<Type> {
    search_identifier_path_names_with_filter(
        &identifier_path.names(),
        context.schema,
        context.source(),
        &context.current_namespace().map_or(vec![], |n| n.str_path()),
        filter,
        availability,
    )
}