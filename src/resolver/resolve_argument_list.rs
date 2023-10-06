use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::argument_list::ArgumentList;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::resolver::resolver_context::ResolverContext;

pub(super) struct CallableVariant<'a> {
    pub(super) generics_declaration: Option<&'a GenericsDeclaration>,
    pub(super) argument_list_declaration: Option<&'a ArgumentListDeclaration>,
    pub(super) generics_contraint: Option<&'a GenericsConstraint>,
}

pub(super) fn resolve_argument_list<'a>(
    argument_list: Option<&'a ArgumentList>,
    callable_variants: Vec<CallableVariant<'a>>,
    context: &'a ResolverContext<'a>,
) {

}