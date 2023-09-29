use crate::ast::identifier::Identifier;
use crate::ast::reference::{Reference, ReferenceType};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_identifier(
    identifier: &Identifier,
    context: &mut ResolverContext,
    reference_type: ReferenceType
) -> Option<Reference> {

}