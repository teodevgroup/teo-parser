use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::r#type::TypeExpr;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_type_expr<'a>(
    type_expr: &'a TypeExpr,
    generics_declaration: Option<&'a GenericsDeclaration>,
    generics_constraint: Option<&'a GenericsConstraint>,
    context: &'a ResolverContext<'a>
) {

}