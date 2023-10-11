use crate::ast::pipeline::Pipeline;
use crate::ast::reference::ReferenceType;
use crate::ast::unit::Unit;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_identifier::resolve_identifier;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_pipeline<'a>(pipeline: &'a Pipeline, context: &'a ResolverContext<'a>, mut expected: &Type) -> Type {
    if expected.is_optional() {
        expected = expected.unwrap_optional();
    }
    let undetermined = Type::Undetermined;
    let r#type = if expected.is_pipeline() {
        expected
    } else if let Some(types) = expected.as_union() {
        types.iter().find_map(|t| if t.is_pipeline() {
            Some(t)
        } else {
            None
        }).unwrap_or(&undetermined)
    } else {
        &undetermined
    };
    resolve_pipeline_unit(pipeline.unit.as_ref(), context, r#type)
}

pub(super) fn resolve_pipeline_unit<'a>(unit: &'a Unit, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    let current = resolve_identifier(
        unit.expressions.get(0).unwrap().as_identifier().unwrap(),
        context,
        ReferenceType::PipelineItem
    );
    for (index, expression) in unit.expressions.iter().enumerate() {
        if index == 0 { continue }

    }
    Type::Undetermined
}