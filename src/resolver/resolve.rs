use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::diagnostics::diagnostics::Diagnostics;
use crate::resolver::resolve_source::{resolve_source_consumers, resolve_source_references_check, resolve_source_references_first, resolve_source_references_second, resolve_source_types};
use crate::resolver::resolver_context::ResolverContext;

pub(crate) fn resolve(schema: &Schema, diagnostics: &mut Diagnostics) {
    let context = ResolverContext::new(diagnostics, schema);
    // handle builtin
    resolve_sources(&context, &schema.builtin_sources());
    // handle user sources
    resolve_sources(&context, &schema.user_sources());
}

fn resolve_sources(context: &ResolverContext, sources: &Vec<&Source>) {
    for source in sources {
        context.start_source(source);
        resolve_source_types(&context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_references_first(&context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_references_second(&context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_references_check(&context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_consumers(&context);
    }
}