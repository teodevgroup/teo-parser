use crate::ast::schema::Schema;
use crate::diagnostics::diagnostics::Diagnostics;
use crate::resolver::resolve_source::{resolve_source_first, resolve_source_second, resolve_source_third};
use crate::resolver::resolver_context::ResolverContext;

pub(crate) fn resolve(schema: &Schema, diagnostics: &mut Diagnostics) {
    let context = ResolverContext::new(diagnostics, schema);
    // handle builtin
    for source in schema.builtin_sources() {
        context.start_source(source);
        resolve_source_first(&context);
    }
    for source in schema.builtin_sources() {
        context.start_source(source);
        resolve_source_second(&context);
    }
    for source in schema.builtin_sources() {
        context.start_source(source);
        resolve_source_third(&context);
    }
    // handle user sources
    for source in schema.user_sources() {
        context.start_source(source);
        resolve_source_first(&context);
    }
    for source in schema.user_sources() {
        context.start_source(source);
        resolve_source_second(&context);
    }
    for source in schema.user_sources() {
        context.start_source(source);
        resolve_source_third(&context);
    }
}