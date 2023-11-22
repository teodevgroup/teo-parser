use std::collections::BTreeMap;
use crate::expr::{ExprInfo, ReferenceType};
use crate::ast::pipeline::Pipeline;
use crate::ast::span::Span;
use crate::ast::type_info::TypeInfo;
use crate::ast::unit::Unit;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_argument_list::resolve_argument_list;
use crate::resolver::resolve_identifier::resolve_identifier_path_names_with_filter_to_expr_info;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::utils::top_filter::top_filter_for_pipeline;

pub(super) fn resolve_pipeline<'a>(pipeline: &'a Pipeline, context: &'a ResolverContext<'a>, mut expected: &Type, keywords_map: &BTreeMap<Keyword, Type>) -> ExprInfo {
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
    ExprInfo::type_only(resolve_pipeline_unit(pipeline.span, pipeline.unit(), context, r#type, keywords_map))
}

pub(super) fn resolve_pipeline_unit<'a>(span: Span, unit: &'a Unit, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>) -> Type {
    if let Some(empty_dot) = unit.empty_dot() {
        context.insert_diagnostics_error(empty_dot.span, "empty reference");
    }
    let mut has_errors = false;
    let mut current_input_type = if let Some((input, _)) = expected.as_pipeline() {
        input.clone()
    } else {
        Type::Any
    };
    let mut current_space: Vec<String> = vec![];
    for (index, expression) in unit.expressions().enumerate() {
        if let Some(identifier) = expression.kind.as_identifier() {
            let mut names: Vec<&str> = current_space.iter().map(AsRef::as_ref).collect();
            names.push(identifier.name());
            if let Some(expr_info) = resolve_identifier_path_names_with_filter_to_expr_info(
                &names,
                context.schema,
                context.source(),
                &context.current_namespace().map_or(vec![], |n| n.str_path()),
                &top_filter_for_pipeline(),
                context.current_availability(),
                context,
            ) {
                if expr_info.reference_info().is_none() {
                    context.insert_diagnostics_error(identifier.span, "identifier not found");
                    has_errors = true;
                }
                match expr_info.reference_info().unwrap().r#type {
                    ReferenceType::Namespace => current_space = expr_info.reference_info().unwrap().reference.string_path().clone(),
                    ReferenceType::PipelineItemDeclaration => {
                        let pipeline_item_declaration = context.schema.find_top_by_path(expr_info.reference_info().unwrap().reference.path()).unwrap().as_pipeline_item_declaration().unwrap();
                        let pipeline_type_context = TypeInfo {
                            passed_in: current_input_type.clone()
                        };
                        let argument_list = unit.expression_at(index + 1).map(|e| e.kind.as_argument_list()).flatten();
                        current_input_type = resolve_argument_list(identifier.span, argument_list, pipeline_item_declaration.callable_variants(), keywords_map, context, Some(&pipeline_type_context)).unwrap();
                        current_space = vec![];
                    }
                    _ => ()
                }
            } else {
                context.insert_diagnostics_error(identifier.span, "identifier not found");
                has_errors = true;
            }
        }
    }
    if let Some((_, output)) = expected.as_pipeline() {
        if !output.test(&current_input_type) {
            if !current_input_type.is_undetermined() {
                context.insert_diagnostics_error(span, format!("unexpected pipeline output: expect {output}, found {current_input_type}"));
            }
            has_errors = true;
        }
    }
    if has_errors {
        expected.clone()
    } else if let Some((input, _output)) = expected.as_pipeline() {
        Type::Pipeline(Box::new(input.clone()), Box::new(current_input_type))
    } else {
        Type::Undetermined
    }
}