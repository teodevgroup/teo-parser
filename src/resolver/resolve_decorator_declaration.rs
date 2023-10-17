use crate::ast::availability::Availability;
use crate::ast::decorator_declaration::{DecoratorDeclaration, DecoratorDeclarationVariant};
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolve_generics::{resolve_generics_constraint, resolve_generics_declaration};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_decorator_declaration<'a>(decorator_declaration: &'a DecoratorDeclaration, context: &'a ResolverContext<'a>) {
    if let Some(generics_declaration) = &decorator_declaration.generics_declaration {
        resolve_generics_declaration(generics_declaration, context);
        if let Some(generics_constraint) = &decorator_declaration.generics_constraint {
            resolve_generics_constraint(generics_constraint, context, generics_declaration, decorator_declaration.availability);
        }
    }
    if let Some(argument_list_declaration) = &decorator_declaration.argument_list_declaration {
        resolve_argument_list_declaration(
            argument_list_declaration,
            &if let Some(generics_declaration) = decorator_declaration.generics_declaration.as_ref() {
                vec![generics_declaration]
            } else {
                vec![]
            },
            &if let Some(generics_constraint) = decorator_declaration.generics_constraint.as_ref() {
                vec![generics_constraint]
            } else {
                vec![]
            },
            context,
            decorator_declaration.availability
        )
    }
    for variant in &decorator_declaration.variants {
        resolve_decorator_declaration_variant(variant, context, decorator_declaration.availability);
    }
}

fn resolve_decorator_declaration_variant<'a>(
    decorator_declaration_variant: &'a DecoratorDeclarationVariant,
    context: &'a ResolverContext<'a>,
    availability: Availability,
) {
    if let Some(generics_declaration) = &decorator_declaration_variant.generics_declaration {
        resolve_generics_declaration(generics_declaration, context);
        if let Some(generics_constraint) = &decorator_declaration_variant.generics_constraint {
            resolve_generics_constraint(generics_constraint, context, generics_declaration, availability);
        }
    }
    if let Some(argument_list_declaration) = &decorator_declaration_variant.argument_list_declaration {
        resolve_argument_list_declaration(
            argument_list_declaration,
            &if let Some(generics_declaration) = decorator_declaration_variant.generics_declaration.as_ref() {
                vec![generics_declaration]
            } else {
                vec![]
            },
            &if let Some(generics_constraint) = decorator_declaration_variant.generics_constraint.as_ref() {
                vec![generics_constraint]
            } else {
                vec![]
            },
            context,
            availability
        )
    }
}