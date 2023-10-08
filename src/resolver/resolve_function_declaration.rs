use crate::ast::field::{Field, FieldClass, FieldResolved};
use crate::ast::function_declaration::FunctionDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolve_type_expr::resolve_type_expr;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_function_declaration<'a>(
    function_declaration: &'a FunctionDeclaration,
    generics_declaration: Option<&'a GenericsDeclaration>,
    generics_constraint: Option<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>,
) {
    if let Some(argument_list_declaration) = &function_declaration.argument_list_declaration {
        resolve_argument_list_declaration(
            argument_list_declaration,
            generics_declaration,
            generics_constraint,
            context
        );
    }
    resolve_type_expr(
        &function_declaration.return_type,
        generics_declaration,
        generics_constraint,
        context
    );
}