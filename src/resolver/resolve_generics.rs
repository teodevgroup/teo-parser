use itertools::Itertools;
use crate::ast::generics::GenericsDeclaration;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_generics_declaration<'a>(
    generics_declaration: &'a GenericsDeclaration,
    context: &'a ResolverContext<'a>
) {
    generics_declaration.identifiers.iter().duplicates_by(|i| i.name()).for_each(|i| {
        context.insert_diagnostics_error(i.span, "GenericsError: duplicated name")
    })
}