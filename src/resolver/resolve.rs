use crate::ast::schema::Schema;
use crate::diagnostics::diagnostics::Diagnostics;
use crate::resolver::resolve_source::{resolve_source_first, resolve_source_second, resolve_source_third};
use crate::resolver::resolver_context::ResolverContext;

pub(crate) fn resolve(schema: &Schema, diagnostics: &mut Diagnostics) {
    let mut context = ResolverContext::new(diagnostics);
    for source in schema.sources() {
        resolve_source_first(source, schema, &mut context);
    }
    for source in schema.sources() {
        resolve_source_second(source, schema, &mut context);
    }
    for source in schema.sources() {
        resolve_source_third(source, schema, &mut context);
    }
}