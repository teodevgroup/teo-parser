use crate::ast::middleware::Middleware;
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_middleware<'a>(middleware: &'a Middleware, context: &'a ResolverContext<'a>) {
    if context.has_examined_middleware_path(&middleware.string_path) {
        context.insert_diagnostics_error(middleware.identifier.span, "DefinitionError: duplicated definition of middleware");
    } else {
        context.add_examined_middleware_path(middleware.string_path.clone());
    }
    if let Some(argument_list_declaration) = &middleware.argument_list_declaration {
        resolve_argument_list_declaration(argument_list_declaration, &vec![], &vec![], context, context.current_availability())
    }
}