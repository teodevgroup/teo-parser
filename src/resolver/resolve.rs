use crate::ast::schema::Schema;
use crate::diagnostics::diagnostics::Diagnostics;
use crate::resolver::resolve_source::{resolve_source_first, resolve_source_second, resolve_source_third};
use crate::resolver::resolver_context::ResolverContext;

pub(crate) fn resolve(schema: &Schema, diagnostics: &mut Diagnostics) {
    let mut context = ResolverContext::new(diagnostics, schema);
    for source in schema.sources() {
        context.start_source(source);
        resolve_source_first(&mut context);
    }
    for source in schema.sources() {
        context.start_source(source);
        resolve_source_second(&mut context);
    }
    for source in schema.sources() {
        context.start_source(source);
        resolve_source_third(&mut context);
    }
}