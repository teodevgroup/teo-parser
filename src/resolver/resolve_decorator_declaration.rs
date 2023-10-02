use crate::ast::decorator_declaration::{DecoratorDeclaration, DecoratorDeclarationVariant};
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_decorator_declaration<'a>(decorator_declaration: &'a DecoratorDeclaration, context: &'a ResolverContext<'a>) {
    if let Some(argument_list_declaration) = &decorator_declaration.argument_list_declaration {
        resolve_argument_list_declaration(
            argument_list_declaration,
            decorator_declaration.generics_declaration.as_ref(),
            decorator_declaration.generics_constraint.as_ref(),
            context,
        )
    }
    for variant in &decorator_declaration.variants {
        resolve_decorator_declaration_variant(variant, context);
    }
}

fn resolve_decorator_declaration_variant<'a>(
    decorator_declaration_variant: &'a DecoratorDeclarationVariant,
    context: &'a ResolverContext<'a>
) {
    if let Some(argument_list_declaration) = &decorator_declaration_variant.argument_list_declaration {
        resolve_argument_list_declaration(
            argument_list_declaration,
            decorator_declaration_variant.generics_declaration.as_ref(),
            decorator_declaration_variant.generics_constraint.as_ref(),
            context,
        )
    }
}