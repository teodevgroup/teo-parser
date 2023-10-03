use crate::ast::middleware::Middleware;
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_middleware<'a>(middleware: &'a Middleware, context: &'a ResolverContext<'a>) {
    if let Some(argument_list_declaration) = &middleware.argument_list_declaration {
        resolve_argument_list_declaration(argument_list_declaration, None, None, context)
    }
}