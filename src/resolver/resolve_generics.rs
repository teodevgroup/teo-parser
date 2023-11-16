use itertools::Itertools;
use maplit::btreemap;
use crate::availability::Availability;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_generics_declaration<'a>(
    generics_declaration: &'a GenericsDeclaration,
    existing_generics_declarations: &Vec<&'a GenericsDeclaration>,
    context: &'a ResolverContext<'a>
) {
    generics_declaration.identifiers.iter().duplicates_by(|i| i.name()).for_each(|i| {
        context.insert_diagnostics_error(i.span, "duplicated generics identifier")
    });
    for identifier in &generics_declaration.identifiers {
        for g in existing_generics_declarations {
            if g.identifiers.iter().find(|i| i.name() == identifier.name()).is_some() {
                context.insert_diagnostics_error(identifier.span, "duplicated generics identifier")
            }
        }
    }
}

pub(super) fn resolve_generics_constraint<'a>(
    generics_constraint: &'a GenericsConstraint,
    context: &'a ResolverContext<'a>,
    generics_declaration: &'a GenericsDeclaration,
    availability: Availability,
) {
    generics_constraint.items.iter().duplicates_by(|i| i.identifier().name()).for_each(|i| {
        context.insert_diagnostics_error(i.span, "duplicated generics constraint")
    });
    for item in &generics_constraint.items {
        if generics_declaration.identifiers.iter().find(|i| i.name() == item.identifier().name()).is_none() {
            context.insert_diagnostics_error(item.identifier().span, "undefined generics identifier")
        }
        resolve_type_expr(
            &item.type_expr,
            &vec![generics_declaration],
            &vec![],
            &btreemap! {},
            context,
            availability,
        )
    }
}