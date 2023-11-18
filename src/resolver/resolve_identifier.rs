use std::sync::Arc;

use crate::availability::Availability;
use crate::expr::ExprInfo;
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::node::Node;
use crate::ast::reference_space::ReferenceSpace;

use crate::resolver::resolver_context::ResolverContext;
use crate::search::search_identifier_path::search_identifier_path_names_with_filter_to_type_and_value;
use crate::traits::named_identifiable::NamedIdentifiable;
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

pub(super) fn resolve_identifier(
    identifier: &Identifier,
    context: &ResolverContext,
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

pub(super) fn resolve_identifier_with_filter(
    identifier: &Identifier,
    context: &ResolverContext,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<ExprInfo> {
    search_identifier_path_names_with_filter_to_type_and_value(
        &vec![identifier.name()],
        context.schema,
        context.source(),
        &context.current_namespace().map_or(vec![], |n| n.str_path()),
        filter,
        availability,
    )
}

pub(super) fn resolve_identifier_path(
    identifier_path: &IdentifierPath,
    context: &ResolverContext,
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

pub(super) fn resolve_identifier_path_with_filter(
    identifier_path: &IdentifierPath,
    context: &ResolverContext,
    filter: &Arc<dyn Fn(&Node) -> bool>,
    availability: Availability,
) -> Option<ExprInfo> {
    search_identifier_path_names_with_filter_to_type_and_value(
        &identifier_path.names(),
        context.schema,
        context.source(),
        &context.current_namespace().map_or(vec![], |n| n.str_path()),
        filter,
        availability,
    )
}