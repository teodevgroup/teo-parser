use crate::ast::pipeline::Pipeline;
use crate::ast::unit::Unit;
use crate::r#type::r#type::Type;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_pipeline<'a>(pipeline: &'a Pipeline, context: &'a ResolverContext<'a>) -> Type {
    resolve_pipeline_unit(pipeline.unit.as_ref(), context)
}

pub(super) fn resolve_pipeline_unit<'a>(unit: &'a Unit, context: &'a ResolverContext<'a>) -> Type {
    //unit.expressions
    Type::Undetermined
}