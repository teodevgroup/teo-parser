use std::collections::{BTreeMap, HashMap};
use maplit::{btreemap, btreeset};
use crate::ast::argument::ArgumentResolved;
use crate::ast::argument_list::ArgumentList;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::generics::GenericsConstraint;
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
    keywords_map: &BTreeMap<Keyword, Type>,
    context: &'a ResolverContext<'a>,
    pipeline_type_context: Option<&'b TypeInfo>,
) -> Option<Type> {
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
                    context.insert_diagnostics_warning(*warning.span(), warning.message());
                }
                return t;
            }
        }
        context.insert_diagnostics_error(callable_span, "variant not found for arguments");
        return Some(Type::Undetermined);
    }
}

fn try_resolve_argument_list_for_callable_variant<'a, 'b>(
    callable_span: Span,
    argument_list: Option<&'a ArgumentList>,
    callable_variant: &CallableVariant<'a>,
    keywords_map: &BTreeMap<Keyword, Type>,
    context: &'a ResolverContext<'a>,
    type_info: Option<&'b TypeInfo>,
) -> (Vec<DiagnosticsError>, Vec<DiagnosticsWarning>, Option<Type>) {
    // declare errors and warnings
    let mut errors = vec![];
    let mut warnings = vec![];
    // collect generics identifiers
    let mut generic_identifiers = btreeset!{};
    for g in &callable_variant.generics_declarations {
        for i in &g.identifiers {
            generic_identifiers.insert(i.name().to_string());
        }
    }
    let mut generics_map = btreemap!{};
    let mut passed_in = None;
    // figure out generics by guessing
    if let Some(type_info) = type_info {
        passed_in = Some(type_info.passed_in.clone());
        if type_info.passed_in.contains_generics() {
            if !callable_variant.pipeline_input.as_ref().unwrap().contains_generics() {
                passed_in = Some(callable_variant.pipeline_input.as_ref().unwrap().clone());
            }
        } else {
            if let Some(pipeline_input) = &callable_variant.pipeline_input {
                if pipeline_input.contains_generics() {
                    guess_extend_and_check(
                        callable_span,
                        callable_variant,
                        pipeline_input,
                        passed_in.as_ref().unwrap(),
                        &mut generics_map,
                        keywords_map,
                        &mut errors,
                        context,
                    );
                }
            }
        }
    }
    // test input type matching
    if let Some(pipeline_input) = &callable_variant.pipeline_input {
        let expected = pipeline_input.replace_keywords(keywords_map).replace_generics(&generics_map);
        let found = passed_in.as_ref().unwrap().replace_generics(&generics_map).replace_keywords(keywords_map);
        if !expected.test(&found) {
            errors.push(context.generate_diagnostics_error(callable_span, format!("unexpected pipeline input: expect {expected}, found {found}")));
        }
    }
    // normal process handling
    if let Some(argument_list_declaration) = callable_variant.argument_list_declaration {
        let mut declaration_names: Vec<&str> = argument_list_declaration.argument_declarations.iter().map(|d| d.name.name()).collect();
        // match named arguments
        if let Some(argument_list) = argument_list {
            for named_argument in argument_list.arguments().iter().filter(|a| a.name.is_some()) {
                if let Some(argument_declaration) = argument_list_declaration.get(named_argument.name.as_ref().unwrap().name()) {
                    let desired_type_original = argument_declaration.type_expr.resolved();
                    let desired_type = flatten_field_type_reference(desired_type_original.replace_keywords(keywords_map).replace_generics(&generics_map), context);
                    resolve_expression(&named_argument.value, context, &desired_type, keywords_map);
                    if !desired_type.test(named_argument.value.resolved().r#type()) {
                        if !named_argument.value.resolved().r#type.is_undetermined() {
                            errors.push(context.generate_diagnostics_error(named_argument.value.span(), format!("expect {}, found {}", desired_type, named_argument.value.resolved().r#type())))
                        }
                    } else if desired_type_original.is_generic_item() && desired_type.is_synthesized_enum_variant_reference() {
                        generics_map.insert(desired_type_original.as_generic_item().unwrap().to_owned(), named_argument.value.resolved().r#type.clone());
                    } else if desired_type_original.contains_generics() && desired_type.contains_generics() {
                        guess_extend_and_check(
                            callable_span,
                            callable_variant,
                            &desired_type,
                            named_argument.value.resolved().r#type(),
                            &mut generics_map,
                            keywords_map,
                            &mut errors,
                            context,
                        );
                    }
                    named_argument.resolve(ArgumentResolved {
                        name: named_argument.name.as_ref().unwrap().name.clone().to_string(),
                        expect: argument_declaration.type_expr.resolved().clone(),
                    });
                    declaration_names = declaration_names.iter().filter(|d| (**d) != argument_declaration.name.name()).map(|s| *s).collect();
                } else {
                    let undetermined = Type::Undetermined;
                    resolve_expression(&named_argument.value, context, &undetermined, keywords_map);
                    errors.push(context.generate_diagnostics_error(named_argument.name.as_ref().unwrap().span, "Undefined argument"))
                }
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
        if let Some(argument_list) = argument_list {
            for unnamed_argument in argument_list.arguments().iter().filter(|a| a.name.is_none()) {
                if let Some(name) = declaration_names.first() {
                    if let Some(argument_declaration) = argument_list_declaration.get(name) {
                        let desired_type_original = argument_declaration.type_expr.resolved();
                        let desired_type = flatten_field_type_reference(desired_type_original.replace_keywords(keywords_map).replace_generics(&generics_map), context);
                        resolve_expression(&unnamed_argument.value, context, &desired_type, keywords_map);
                        if !desired_type.test(unnamed_argument.value.resolved().r#type()) {
                            if !unnamed_argument.value.resolved().r#type().is_undetermined() {
                                errors.push(context.generate_diagnostics_error(unnamed_argument.value.span(), format!("expect {}, found {}", desired_type, unnamed_argument.value.resolved().r#type())))
                            }
                        } else if desired_type_original.is_generic_item() && desired_type.is_synthesized_enum_variant_reference() {
                            generics_map.insert(desired_type_original.as_generic_item().unwrap().to_owned(), unnamed_argument.value.resolved().r#type().clone());
                        } else if desired_type_original.contains_generics() && desired_type.contains_generics() {
                            guess_extend_and_check(
                                callable_span,
                                callable_variant,
                                &desired_type,
                                unnamed_argument.value.resolved().r#type(),
                                &mut generics_map,
                                keywords_map,
                                &mut errors,
                                context,
                            );
                        }
                        unnamed_argument.resolve(ArgumentResolved {
                            name: name.to_string(),
                            expect: argument_declaration.type_expr.resolved().clone(),
                        });
                        declaration_names = declaration_names.iter().filter(|d| *d != name).map(|s| *s).collect();
                    }
                } else {
                    errors.push(context.generate_diagnostics_error(unnamed_argument.span, "Redundant argument"));
                }
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
        if let Some(argument_list) = argument_list {
            if !argument_list.arguments().is_empty() {
                errors.push(context.generate_diagnostics_error(argument_list.span, "Callable requires no arguments"));
            }
        }
    }
    (errors, warnings, callable_variant.pipeline_output.clone().map(|t| flatten_field_type_reference(t.replace_keywords(keywords_map).replace_generics(&generics_map), context)))
}

fn guess_generics_by_pipeline_input_and_passed_in<'a>(unresolved: &'a Type, explicit: &'a Type) -> Result<BTreeMap<String, Type>, String> {
    if !unresolved.contains_generics() && !explicit.contains_generics() {
        return Ok(btreemap! {})
    }
    let mut unresolved = unresolved;
    let mut explicit = explicit;
    // direct match
    if let Some(identifier) = unresolved.as_generic_item() {
        return Ok(btreemap!{identifier.to_string() => explicit.clone()})
    }
    // unwrap optional
    if let Some(inner) = unresolved.as_optional() {
        unresolved = inner;
        if explicit.is_optional() {
            explicit = explicit.unwrap_optional();
        }
    }
    if let Some(identifier) = unresolved.as_generic_item() {
        return Ok(btreemap!{identifier.to_string() => explicit.clone()})
    }
    // unwrap in types
    if unresolved.is_array() && explicit.is_array() {
        return guess_generics_by_pipeline_input_and_passed_in(unresolved.as_array().unwrap(), explicit.as_array().unwrap());
    } else if unresolved.is_dictionary() && explicit.is_dictionary() {
        return guess_generics_by_pipeline_input_and_passed_in(unresolved.as_dictionary().unwrap(), explicit.as_dictionary().unwrap());
    } else if unresolved.is_pipeline() && explicit.is_pipeline() {
        let mut result = btreemap! {};
        result.extend(guess_generics_by_pipeline_input_and_passed_in(unresolved.as_pipeline().unwrap().0, explicit.as_pipeline().unwrap().0)?);
        result.extend(guess_generics_by_pipeline_input_and_passed_in(unresolved.as_pipeline().unwrap().1, explicit.as_pipeline().unwrap().1)?);
        return Ok(result);
    }
    Err(format!("cannot resolve generics: unresolved: {}, explicit: {}", unresolved, explicit))
}

fn validate_generics_map_with_constraint_info<'a>(
    span: Span,
    generics_map: &BTreeMap<String, Type>,
    keywords_map: &BTreeMap<Keyword, Type>,
    generics_constraints: &Vec<&GenericsConstraint>,
    context: &'a ResolverContext<'a>,
) -> Vec<DiagnosticsError> {
    let mut results = vec![];
    for (name, t) in generics_map {
        for constraint in generics_constraints {
            for item in &constraint.items {
                if item.identifier.name() == name {
                    let mut generics_map_without_name = generics_map.clone();
                    generics_map_without_name.remove(name);
                    if !t.constraint_test(&item.type_expr.resolved().replace_generics(&generics_map_without_name).replace_keywords(keywords_map)) {
                        results.push(context.generate_diagnostics_error(span, format!("type {} doesn't satisfy {}", t, item.type_expr.resolved())))
                    }
                }
            }
        }
    }
    results
}

fn guess_generics_by_constraints<'a>(
    generics_map: &BTreeMap<String, Type>,
    keywords_map: &BTreeMap<Keyword, Type>,
    generics_constraints: &Vec<&GenericsConstraint>,
) -> BTreeMap<String, Type> {
    let mut retval = btreemap! {};
    for constraint in generics_constraints {
        for item in &constraint.items {
            if !generics_map.contains_key(item.identifier.name()) {
                let new_type = item.type_expr.resolved().replace_keywords(keywords_map).replace_generics(generics_map).flatten();
                if !new_type.contains_generics() {
                    retval.insert(item.identifier.name.clone(), new_type);
                }
            }
        }
    }
    retval
}

fn flatten_field_type_reference<'a>(t: Type, context: &'a ResolverContext<'a>) -> Type {
    t.replace_field_type(|container: &Type, reference: &Type| {
        if let Some(field_name) = reference.as_field_name() {
            match container {
                Type::ModelReference(reference) => {
                    let model = context.schema.find_top_by_path(reference.path()).unwrap().as_model().unwrap();
                    let field = model.fields.iter().find(|f| f.identifier.name() == field_name).unwrap();
                    field.type_expr.resolved().clone()
                },
                Type::InterfaceReference(reference, types) => {
                    let interface = context.schema.find_top_by_path(reference.path()).unwrap().as_interface_declaration().unwrap();
                    let field = interface.fields.iter().find(|f| f.identifier.name() == field_name).unwrap();
                    field.type_expr.resolved().clone()
                },
                _ => Type::Undetermined
            }
        } else {
            Type::Undetermined
        }
    })
}

fn guess_extend_and_check<'a>(
    callable_span: Span,
    callable_variant: &CallableVariant,
    unresolved: &Type,
    explicit: &Type,
    generics_map: &mut BTreeMap<String, Type>,
    keywords_map: &BTreeMap<Keyword, Type>,
    errors: &mut Vec<DiagnosticsError>,
    context: &'a ResolverContext<'a>,
) {
    match guess_generics_by_pipeline_input_and_passed_in(unresolved, explicit) {
        Ok(map) => {
            generics_map.extend(map);
        },
        Err(err) => {
            errors.push(context.generate_diagnostics_error(callable_span, err));
        }
    }
    // generics constraint checking
    for e in validate_generics_map_with_constraint_info(callable_span, &generics_map, keywords_map, &callable_variant.generics_constraints, context) {
        errors.push(e);
    }
    // guessing more by constraints
    generics_map.extend(guess_generics_by_constraints(&generics_map, keywords_map, &callable_variant.generics_constraints));
}