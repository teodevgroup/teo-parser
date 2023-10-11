use std::collections::{BTreeMap, HashMap};
use maplit::{btreemap, btreeset};
use crate::ast::argument::ArgumentResolved;
use crate::ast::argument_list::ArgumentList;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::type_info::TypeInfo;
use crate::ast::span::Span;
use crate::diagnostics::diagnostics::{DiagnosticsError, DiagnosticsLog, DiagnosticsWarning};
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_argument_list<'a, 'b>(
    callable_span: Span,
    argument_list: Option<&'a ArgumentList>,
    callable_variants: Vec<CallableVariant<'a>>,
    keywords_map: &BTreeMap<Keyword, &Type>,
    context: &'a ResolverContext<'a>,
    pipeline_type_context: Option<&'b TypeInfo>,
) -> Option<Type> {
    if let Some(argument_list) = argument_list {
        if callable_variants.len() == 1 {
            let (errors, warnings, t) = try_resolve_argument_list_for_callable_variant(
                callable_span,
                argument_list,
                callable_variants.first().unwrap(),
                keywords_map,
                context,
                pipeline_type_context,
            );
            for error in errors {
                context.insert_diagnostics_error(*error.span(), error.message());
            }
            for warning in warnings {
                context.insert_diagnostics_error(*warning.span(), warning.message());
            }
            return t;
        } else {
            for callable_variant in &callable_variants {
                let (errors, warnings, t) = try_resolve_argument_list_for_callable_variant(
                    callable_span,
                    argument_list,
                    callable_variant,
                    keywords_map,
                    context,
                    pipeline_type_context,
                );
                if errors.is_empty() {
                    for warning in warnings {
                        context.insert_diagnostics_error(*warning.span(), warning.message());
                    }
                    return t;
                }
            }
            context.insert_diagnostics_error(argument_list.span, "Argument list doesn't match any callable variants");
            return Some(Type::Undetermined);
        }
    } else {
        for callable_variant in &callable_variants {
            if let Some(argument_list_declaration) = callable_variant.argument_list_declaration {
                if argument_list_declaration.every_argument_is_optional() {
                    return callable_variant.pipeline_output.clone(); // todo: replace generics
                }
            } else {
                return callable_variant.pipeline_output.clone(); // todo: replace generics
            }
        }
        context.insert_diagnostics_error(callable_span, "Callable requires arguments");
        return Some(Type::Undetermined)
    }
}

fn try_resolve_argument_list_for_callable_variant<'a, 'b>(
    callable_span: Span,
    argument_list: &'a ArgumentList,
    callable_variant: &CallableVariant<'a>,
    keywords_map: &BTreeMap<Keyword, &Type>,
    context: &'a ResolverContext<'a>,
    type_info: Option<&'b TypeInfo>,
) -> (Vec<DiagnosticsError>, Vec<DiagnosticsWarning>, Option<Type>) {
    // declare errors and warnings
    let mut errors = vec![];
    let mut warnings = vec![];
    // figure out generics by guessing
    let mut generic_identifiers = btreeset!{};
    for g in &callable_variant.generics_declarations {
        for i in &g.identifiers {
            generic_identifiers.insert(i.name().to_string());
        }
    }
    let mut generics_map = btreemap!{};
    if let Some(type_info) = type_info {
        if let Some(pipeline_input) = &callable_variant.pipeline_input {
            if pipeline_input.contains_generics() {
                match guess_generics_by_pipeline_input_and_passed_in(pipeline_input, &type_info.passed_in) {
                    Ok(map) => generics_map.extend(map),
                    Err(err) => errors.push(context.generate_diagnostics_error(callable_span, err))
                }
            }
        }
    }
    // normal process handling
    if let Some(argument_list_declaration) = callable_variant.argument_list_declaration {
        let mut declaration_names: Vec<&str> = argument_list_declaration.argument_declarations.iter().map(|d| d.name.name()).collect();
        // match named arguments
        for named_argument in argument_list.arguments().iter().filter(|a| a.name.is_some()) {
            if let Some(argument_declaration) = argument_list_declaration.get(named_argument.name.as_ref().unwrap().name()) {
                let desired_type = argument_declaration.type_expr.resolved().replace_keywords(keywords_map).replace_generics(&generics_map);
                resolve_expression(&named_argument.value, context, &desired_type);
                if !desired_type.test(named_argument.value.resolved()) {
                    errors.push(context.generate_diagnostics_error(named_argument.value.span(), "Argument value is of wrong type"))
                }
                declaration_names = declaration_names.iter().filter(|d| (**d) != argument_declaration.name.name()).map(|s| *s).collect();
            } else {
                let undetermined = Type::Undetermined;
                resolve_expression(&named_argument.value, context, &undetermined);
                errors.push(context.generate_diagnostics_error(named_argument.name.as_ref().unwrap().span, "Undefined argument"))
            }
        }
        // remove named optional declarations and fire errors for named required declarations
        for name in declaration_names.clone() {
            if let Some(argument_declaration) = argument_list_declaration.get(name) {
                if !argument_declaration.name_optional {
                    if !argument_declaration.type_expr.resolved().is_optional() {
                        errors.push(context.generate_diagnostics_error(argument_declaration.span, format!("Missing argument '{}'", name)));
                    }
                    declaration_names = declaration_names.iter().filter(|d| (**d) != argument_declaration.name.name()).map(|s| *s).collect();
                }
            }
        }
        // match unnamed arguments
        for unnamed_argument in argument_list.arguments().iter().filter(|a| a.name.is_none()) {
            if let Some(name) = declaration_names.first() {
                if let Some(argument_declaration) = argument_list_declaration.get(name) {
                    let desired_type = argument_declaration.type_expr.resolved().replace_keywords(keywords_map).replace_generics(&generics_map);
                    resolve_expression(&unnamed_argument.value, context, &desired_type);
                    if !desired_type.test(unnamed_argument.value.resolved()) {
                        errors.push(context.generate_diagnostics_error(unnamed_argument.value.span(), "Argument value is of wrong type"))
                    }
                    unnamed_argument.resolve(ArgumentResolved {
                        name: name.to_string()
                    });
                    declaration_names = declaration_names.iter().filter(|d| *d != name).map(|s| *s).collect();
                }
            } else {
                errors.push(context.generate_diagnostics_error(unnamed_argument.span, "Redundant argument"));
            }
        }
        // fire errors for required unnamed declarations
        for declaration_name in declaration_names {
            if let Some(argument_declaration) = argument_list_declaration.get(declaration_name) {
                if !argument_declaration.type_expr.resolved().is_optional() {
                    errors.push(context.generate_diagnostics_error(argument_declaration.span, format!("Missing argument '{}'", declaration_name)));
                }
            }
        }
    } else {
        if !argument_list.arguments().is_empty() {
            errors.push(context.generate_diagnostics_error(argument_list.span, "Callable requires no arguments"));
        }
    }
    (errors, warnings, callable_variant.pipeline_output.clone().map(|t| t.replace_keywords(keywords_map).replace_generics(&generics_map)))
}

fn guess_generics_by_pipeline_input_and_passed_in<'a>(mut pipeline_input: &'a Type, mut passed_in: &'a Type) -> Result<BTreeMap<String, &'a Type>, String> {
    if let Some(identifier) = pipeline_input.as_generic_item() {
        return Ok(btreemap!{identifier.to_string() => passed_in})
    }
    if let Some(inner) = pipeline_input.as_optional() {
        pipeline_input = inner;
        if passed_in.is_optional() {
            passed_in = passed_in.unwrap_optional();
        }
    }
    if let Some(identifier) = pipeline_input.as_generic_item() {
        return Ok(btreemap!{identifier.to_string() => passed_in})
    }
    if pipeline_input.is_array() && passed_in.is_array() {
        return guess_generics_by_pipeline_input_and_passed_in(pipeline_input.as_array().unwrap(), passed_in.as_array().unwrap());
    } else if pipeline_input.is_dictionary() && passed_in.is_dictionary() {
        return guess_generics_by_pipeline_input_and_passed_in(pipeline_input.as_dictionary().unwrap(), passed_in.as_dictionary().unwrap());
    }
    Err("Pipeline input and passed in are not match".to_owned())
}