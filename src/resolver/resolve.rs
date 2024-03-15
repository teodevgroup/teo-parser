use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::diagnostics::diagnostics::Diagnostics;
use crate::resolver::resolve_source::{resolve_source_constant_used_check, resolve_source_consumers, resolve_source_interface_shapes, resolve_source_model_declared_shapes, resolve_source_model_fields, resolve_source_model_shapes, resolve_source_references, resolve_source_types};
use crate::resolver::resolver_context::ResolverContext;

pub(crate) fn resolve(schema: &Schema, diagnostics: &mut Diagnostics) {
    let context = ResolverContext::new(diagnostics, schema);
    // handle builtin
    resolve_sources(&context, &schema.builtin_sources());
    // handle user sources
    resolve_sources(&context, &schema.user_sources());
}

fn resolve_sources<'a>(context: &'a ResolverContext<'a>, sources: &Vec<&'a Source>) {
    for source in sources {
        context.start_source(source);
        resolve_source_model_fields(context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_model_shapes(context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_types(context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_model_declared_shapes(context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_interface_shapes(context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_references(context);
    }
    for source in sources {
        context.start_source(source);
        resolve_source_consumers(context);
    }
    for source in sources {
        if !source.builtin {
            context.start_source(source);
            resolve_source_constant_used_check(context);
        }
    }
}