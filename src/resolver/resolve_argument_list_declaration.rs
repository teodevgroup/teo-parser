use crate::ast::argument_declaration::{ArgumentDeclaration, ArgumentListDeclaration};
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_argument_list_declaration<'a>(
    argument_list_declaration: &'a ArgumentListDeclaration,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>
) {
    for argument_declaration in &argument_list_declaration.argument_declarations {
        resolve_argument_declaration(argument_declaration, generics_declaration, generics_constraint, context)
    }
}

fn resolve_argument_declaration<'a>(
    argument_declaration: &'a ArgumentDeclaration,
    generics_declaration: &Vec<&'a GenericsDeclaration>,
    generics_constraint: &Vec<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>
) {
    resolve_type_expr(&argument_declaration.type_expr, generics_declaration, generics_constraint, context)
}