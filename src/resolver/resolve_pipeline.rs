use maplit::btreemap;
use crate::ast::namespace::Namespace;
use crate::ast::pipeline::Pipeline;
use crate::ast::span::Span;
use crate::ast::type_info::TypeInfo;
use crate::ast::top::Top;
use crate::ast::unit::Unit;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_argument_list::resolve_argument_list;
use crate::resolver::resolve_identifier::resolve_identifier_with_filter;
use crate::resolver::resolver_context::ResolverContext;
use crate::utils::top_filter::top_filter_for_pipeline;

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
    resolve_pipeline_unit(pipeline.span, pipeline.unit.as_ref(), context, r#type)
}

pub(super) fn resolve_pipeline_unit<'a>(span: Span, unit: &'a Unit, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    let mut has_errors = false;
    let mut current_input_type = if let Some((input, _)) = expected.as_pipeline() {
        input.clone()
    } else {
        Type::Any
    };
    let mut current_space: Option<&Namespace> = None;
    for (index, expression) in unit.expressions.iter().enumerate() {
        if let Some(identifier) = expression.as_identifier() {
            if let Some(this_top) = if current_space.is_some() {
                current_space.unwrap().find_top_by_name(identifier.name(), &top_filter_for_pipeline())
            } else {
                resolve_identifier_with_filter(identifier, context, &top_filter_for_pipeline()).map(|path| context.schema.find_top_by_path(&path)).flatten()
            } {
                match this_top {
                    Top::Namespace(namespace) => {
                        current_space = Some(namespace);
                    }
                    Top::PipelineItemDeclaration(pipeline_item_declaration) => {
                        let pipeline_type_context = TypeInfo {
                            passed_in: current_input_type.clone()
                        };
                        let argument_list = unit.expressions.get(index + 1).map(|e| e.as_argument_list()).flatten();
                        current_input_type = resolve_argument_list(identifier.span, argument_list, pipeline_item_declaration.callable_variants(), &btreemap!{}, context, Some(&pipeline_type_context)).unwrap();
                        current_space = None;
                    }
                    _ => unreachable!()
                }
            } else {
                context.insert_diagnostics_error(identifier.span, "Identifier is not found");
                has_errors = true;
            }
        }
    }
    if let Some((_, output)) = expected.as_pipeline() {
        if !output.test(&current_input_type) {
            context.insert_diagnostics_error(span, "Output type is unexpected");
            has_errors = true;
        }
    }
    if has_errors {
        expected.clone()
    } else {
        Type::Undetermined
    }
}