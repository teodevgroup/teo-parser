use std::collections::BTreeMap;
use maplit::btreemap;
use teo_teon::types::enum_variant::EnumVariant;
use teo_teon::types::option_variant::OptionVariant;
use teo_teon::Value;
use crate::ast::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::expression::{Expression, ExpressionKind, TypeAndValue};
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::ast::unit::Unit;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::reference::Reference;
use crate::resolver::resolve_argument_list::{resolve_argument_list};
use crate::resolver::resolve_constant::resolve_constant;
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolve_identifier::{resolve_identifier, resolve_identifier_path_with_filter};
use crate::resolver::resolve_interface_shapes::calculate_generics_map;
use crate::resolver::resolver_context::ResolverContext;
use crate::search::search_identifier_path::search_identifier_path_names_with_filter_to_type_and_value;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_unit<'a>(
    unit: &'a Unit,
    context: &'a ResolverContext<'a>,
    expected: &Type,
    keywords_map: &BTreeMap<Keyword, Type>,
) -> TypeAndValue {
    if unit.expressions.len() == 1 {
        return resolve_expression(unit.expressions.get(0).unwrap(), context, expected, keywords_map);
    }
    let mut current: Option<TypeAndValue> = None;
    for (index, expression) in unit.expressions.iter().enumerate() {
        current = Some(resolve_current_item_for_unit(
            if index == 0 { None } else { Some(unit.expressions.get(index - 1).unwrap().span()) },
            current.as_ref(),
            expression,
            context,
            keywords_map
        ));
        if current.as_ref().unwrap().is_undetermined() {
            return current.as_ref().unwrap().clone();
        }
    }
    current.unwrap_or(TypeAndValue::undetermined())
}

fn resolve_current_item_for_unit<'a>(
    last_span: Option<Span>,
    current: Option<&TypeAndValue>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
    keywords_map: &BTreeMap<Keyword, Type>,
) -> TypeAndValue {
    let expected = Type::Undetermined;
    if let Some(current) = current {
        match current.r#type() {
            Type::Optional(inner) => {
                context.insert_diagnostics_error(expression.span(), "value may be null");
                resolve_current_item_for_unit(last_span, Some(&current.with_type(inner.as_ref().clone())), expression, context, keywords_map)
            }
            Type::Null => resolve_builtin_struct_instance_for_unit("Null", &vec![], current, last_span, expression, context, keywords_map),
            Type::Bool => resolve_builtin_struct_instance_for_unit("Bool", &vec![], current, last_span, expression, context, keywords_map),
            Type::Int => resolve_builtin_struct_instance_for_unit("Int", &vec![], current, last_span, expression, context, keywords_map),
            Type::Int64 => resolve_builtin_struct_instance_for_unit("Int64", &vec![], current, last_span, expression, context, keywords_map),
            Type::Float32 => resolve_builtin_struct_instance_for_unit("Float32", &vec![], current, last_span, expression, context, keywords_map),
            Type::Float => resolve_builtin_struct_instance_for_unit("Float", &vec![], current, last_span, expression, context, keywords_map),
            Type::Decimal => resolve_builtin_struct_instance_for_unit("Decimal", &vec![], current, last_span, expression, context, keywords_map),
            Type::String => resolve_builtin_struct_instance_for_unit("String", &vec![], current, last_span, expression, context, keywords_map),
            Type::ObjectId => resolve_builtin_struct_instance_for_unit("ObjectId", &vec![], current, last_span, expression, context, keywords_map),
            Type::Date => resolve_builtin_struct_instance_for_unit("Date", &vec![], current, last_span, expression, context, keywords_map),
            Type::DateTime => resolve_builtin_struct_instance_for_unit("DateTime", &vec![], current, last_span, expression, context, keywords_map),
            Type::File => resolve_builtin_struct_instance_for_unit("File", &vec![], current, last_span, expression, context, keywords_map),
            Type::Regex => resolve_builtin_struct_instance_for_unit("Regex", &vec![], current, last_span, expression, context, keywords_map),
            Type::Array(inner) => resolve_builtin_struct_instance_for_unit("Array", &vec![inner.as_ref()], current, last_span, expression, context, keywords_map),
            Type::Dictionary(inner) => resolve_builtin_struct_instance_for_unit("Dictionary", &vec![inner.as_ref()], current, last_span, expression, context, keywords_map),
            Type::Tuple(types) => resolve_tuple_for_unit(types, current, expression, context),
            Type::Range(inner) => resolve_builtin_struct_instance_for_unit("Range", &vec![inner.as_ref()], current, last_span, expression, context, keywords_map),
            Type::EnumReference(reference) => resolve_enum_reference_for_unit(reference, expression, context),
            Type::EnumVariant(_) => resolve_enum_variant_for_unit(last_span.unwrap(), current, expression, context),
            Type::ConfigReference(reference) => resolve_config_reference_for_unit(reference, expression, context),
            Type::ModelReference(reference) => resolve_model_reference_for_unit(reference, expression, context),
            Type::InterfaceReference(reference, types) => resolve_interface_reference_for_unit(reference, types, expression, context),
            Type::InterfaceObject(reference, types) => resolve_interface_object_for_unit(reference, current, types, expression, context),
            Type::StructReference(reference, types) => resolve_struct_reference_for_unit(last_span.unwrap(), reference, types, expression, context),
            Type::StructObject(reference, types) => resolve_struct_object_for_unit(reference, types, expression, context),
            Type::StructStaticFunctionReference(reference, types) => resolve_struct_static_function_reference_for_unit(last_span.unwrap(), reference, types, expression, context),
            Type::StructInstanceFunctionReference(reference, types) => resolve_struct_instance_function_reference_for_unit(last_span.unwrap(),reference, types, expression, context),
            Type::FunctionReference(_) => todo!(),
            Type::MiddlewareReference(reference) => resolve_middleware_reference_for_unit(last_span.unwrap(), reference, expression, context),
            Type::NamespaceReference(string_path) => resolve_namespace_reference_for_unit(string_path, expression, context),
            _ => TypeAndValue::undetermined(),
        }
    } else {
        resolve_expression(expression, context, &expected, keywords_map)
    }
}

fn resolve_builtin_struct_instance_for_unit<'a>(
    struct_name: &str,
    gens: &Vec<&Type>,
    current: &TypeAndValue,
    last_span: Option<Span>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
    keywords_map: &BTreeMap<Keyword, Type>,
) -> TypeAndValue {
    resolve_struct_instance_for_unit(
        &vec!["std", struct_name],
        gens,
        current,
        last_span,
        expression,
        context,
        keywords_map,
    )
}

fn resolve_struct_instance_for_unit<'a>(
    struct_path: &Vec<&str>,
    gens: &Vec<&Type>,
    current: &TypeAndValue,
    last_span: Option<Span>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
    keywords_map: &BTreeMap<Keyword, Type>,
) -> TypeAndValue {
    let Some(struct_definition) = context.source().find_top_by_string_path(
        struct_path,
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).map(|top| top.as_struct_declaration()).flatten() else {
        context.insert_diagnostics_error(if let Some(last_span) = last_span {
            last_span
        } else {
            expression.span()
        }, "undefined struct");
        return expression.resolve(TypeAndValue::undetermined());
    };
    expression.resolve(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            let Some(instance_function) = struct_definition.instance_function(identifier.name()) else {
                context.insert_diagnostics_error(expression.span(), "undefined instance function");
                return expression.resolve(TypeAndValue::undetermined());
            };
            TypeAndValue::type_only(Type::StructInstanceFunctionReference(Reference::new(instance_function.path.clone(), instance_function.string_path.clone()), gens.iter().map(Clone::clone).map(Clone::clone).collect()))
        },
        ExpressionKind::Subscript(subscript) => {
            let Some(subscript_function) = struct_definition.instance_function("subscript") else {
                context.insert_diagnostics_error(expression.span(), format!("{} is not subscriptable", current.r#type()));
                return expression.resolve(TypeAndValue::undetermined());
            };
            let Some(argument_list_declaration) = subscript_function.argument_list_declaration.as_ref() else {
                return expression.resolve(TypeAndValue::undetermined());
            };
            if argument_list_declaration.argument_declarations.len() != 1 {
                return expression.resolve(TypeAndValue::undetermined());
            }
            let mut map = calculate_generics_map(struct_definition.generics_declaration.as_ref(), &current.r#type.generic_types());
            let argument_declaration = argument_list_declaration.argument_declarations.first().unwrap();
            let expected_type = argument_declaration.type_expr.resolved().replace_generics(&map);
            resolve_expression(subscript.expression.as_ref(), context, &Type::Undetermined, &btreemap! {});
            if expected_type.is_generic_item() {
                map.insert(expected_type.as_generic_item().unwrap().to_string(), subscript.expression.resolved().r#type.clone());
            } else {
                if !expected_type.test(subscript.expression.resolved().r#type()) {
                    context.insert_diagnostics_error(subscript.expression.span(), format!("expect {}, found {}", expected_type, subscript.expression.resolved().r#type()));
                }
            }
            let return_type = subscript_function.return_type.resolved().replace_generics(&map);
            TypeAndValue::type_only(return_type)
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        },
    })
}

fn resolve_tuple_for_unit<'a>(
    types: &Vec<Type>,
    current: &TypeAndValue,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    expression.resolve(match &expression.kind {
        ExpressionKind::IntSubscript(int_subscript) => {
            if int_subscript.index >= types.len() {
                context.insert_diagnostics_error(expression.span(), "index out of bounds");
                TypeAndValue::undetermined()
            } else {
                let t = types.get(int_subscript.index).unwrap().clone();
                let v = if let Some(v) = &current.value {
                    v.as_tuple().map(|t| t.get(int_subscript.index)).flatten().cloned()
                } else {
                    None
                };
                TypeAndValue::new(t, v)
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        },
    })
}

fn resolve_enum_reference_for_unit<'a>(
    reference: &Reference,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let enum_declaration = context.source().find_top_by_string_path(
        &reference.str_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_enum().unwrap();
    expression.resolve(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(m) = enum_declaration.members.iter().find(|m| m.identifier.name() == identifier.name()) {
                TypeAndValue::new(Type::EnumVariant(reference.clone()), Some(if enum_declaration.option {
                    Value::OptionVariant(OptionVariant {
                        value: m.resolved().value.as_int().unwrap(),
                        display: format!(".{}", identifier.name()),
                    })
                } else {
                    Value::EnumVariant(EnumVariant {
                        value: identifier.name().to_owned(),
                        args: None,
                    })
                }))
            } else {
                context.insert_diagnostics_error(expression.span(), "enum member not found");
                TypeAndValue::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        },
    })
}

fn resolve_enum_variant_for_unit<'a>(
    last_span: Span,
    current: &TypeAndValue,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let Some(value) = current.value().map(|v| v.as_enum_variant()).flatten() else {
        context.insert_diagnostics_error(expression.span(), "invalid expression");
        return expression.resolve(TypeAndValue::undetermined());
    };
    if value.args.is_some() {
        context.insert_diagnostics_error(expression.span(), "invalid expression");
        return expression.resolve(TypeAndValue::undetermined());
    }
    let enum_declaration = context.source().find_top_by_string_path(
        &current.r#type.as_enum_variant().unwrap().str_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_enum().unwrap();
    let member_declaration = enum_declaration.members.iter().find(|m| m.identifier.name() == value.value.as_str()).unwrap();
    if let Some(_) = member_declaration.argument_list_declaration.as_ref() {
        match &expression.kind {
            ExpressionKind::ArgumentList(argument_list) => {
                resolve_argument_list(
                    last_span,
                    Some(argument_list),
                    member_declaration.callable_variants(),
                    &btreemap! {},
                    context,
                    None
                );
                let args = argument_list.arguments().iter().map(|argument| {
                    Some((argument.resolved_name()?.to_string(), argument.value.resolved().value.clone()?))
                }).collect::<Option<BTreeMap<String, Value>>>();
                expression.resolve(TypeAndValue::new(current.r#type.clone(), args.map(|args| Value::EnumVariant(EnumVariant {
                    value: value.value.clone(),
                    args: Some(args),
                }))))
            },
            _ => {
                context.insert_diagnostics_error(expression.span(), "invalid expression");
                return expression.resolve(TypeAndValue::undetermined());
            }
        }
    } else {
        context.insert_diagnostics_error(expression.span(), "invalid expression");
        return expression.resolve(TypeAndValue::undetermined());
    }
}

fn resolve_config_reference_for_unit<'a>(
    reference: &Reference,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let config = context.source().find_top_by_string_path(
        &reference.str_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_config().unwrap();
    expression.resolve(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(item) = config.items.iter().find(|item| item.identifier.name() == identifier.name()) {
                item.expression.resolved().clone()
            } else {
                context.insert_diagnostics_error(expression.span(), "config item not found");
                TypeAndValue::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    })
}

fn resolve_model_reference_for_unit<'a>(
    reference: &Reference,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let model = context.source().find_top_by_string_path(
        &reference.str_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_model().unwrap();
    expression.resolve(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(item) = model.fields.iter().find(|item| item.identifier.name() == identifier.name()) {
                TypeAndValue::type_only(Type::ModelFieldReference(Reference::new(item.path.clone(), item.string_path.clone())))
            } else {
                context.insert_diagnostics_error(expression.span(), "model field not found");
                TypeAndValue::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    })
}

fn resolve_interface_reference_for_unit<'a>(
    reference: &Reference,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let interface = context.source().find_top_by_string_path(
        &reference.str_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_interface_declaration().unwrap();
    expression.resolve(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(item) = interface.fields.iter().find(|item| item.identifier.name() == identifier.name()) {
                TypeAndValue::type_only(Type::InterfaceFieldReference(Reference::new(item.path.clone(), item.string_path.clone()), types.clone()))
            } else {
                context.insert_diagnostics_error(expression.span(), "interface field not found");
                TypeAndValue::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    })
}

fn resolve_interface_object_for_unit<'a>(
    reference: &Reference,
    current: &TypeAndValue,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let interface = context.source().find_top_by_string_path(
        &reference.str_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_interface_declaration().unwrap();
    expression.resolve(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(item) = interface.fields.iter().find(|item| item.identifier.name() == identifier.name()) {
                let map = calculate_generics_map(interface.generics_declaration.as_ref(), types);
                TypeAndValue::new(
                    item.type_expr.resolved().replace_generics(&map),
                    current.value().map(|value| value.as_dictionary().map(|d| d.get(&identifier.name).cloned())).flatten().flatten(),
                )
            } else {
                context.insert_diagnostics_error(expression.span(), "interface field not found");
                TypeAndValue::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    })
}

fn resolve_struct_reference_for_unit<'a>(
    last_span: Span,
    reference: &Reference,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let struct_declaration = context.source().find_top_by_string_path(
        &reference.str_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_struct_declaration().unwrap();
    expression.resolve(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(function) = struct_declaration.static_function(identifier.name()) {
                TypeAndValue::type_only(Type::StructStaticFunctionReference(Reference::new(function.path.clone(), function.string_path.clone()), types.clone()))
            } else {
                context.insert_diagnostics_error(expression.span(), "struct static function not found");
                TypeAndValue::undetermined()
            }
        },
        ExpressionKind::ArgumentList(argument_list) => {
            if let Some(new_function) = struct_declaration.static_function("new") {
                resolve_argument_list(
                    last_span,
                    Some(argument_list),
                    new_function.callable_variants(struct_declaration),
                    &struct_declaration.keywords_map(),
                    context,
                    None
                );
                TypeAndValue::type_only(Type::StructObject(Reference::new(struct_declaration.path.clone(), struct_declaration.string_path.clone()), types.clone()))
            } else {
                context.insert_diagnostics_error(expression.span(), "struct initializer not found");
                TypeAndValue::undetermined()
            }
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    })
}

fn resolve_struct_object_for_unit<'a>(
    reference: &Reference,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let struct_declaration = context.source().find_top_by_string_path(
        &reference.str_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_struct_declaration().unwrap();
    expression.resolve(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(function) = struct_declaration.instance_function(identifier.name()) {
                TypeAndValue::type_only(Type::StructInstanceFunctionReference(Reference::new(function.path.clone(), function.string_path.clone()), types.clone()))
            } else {
                context.insert_diagnostics_error(expression.span(), "struct instance function not found");
                TypeAndValue::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    })
}

fn resolve_struct_static_function_reference_for_unit<'a>(
    last_span: Span,
    reference: &Reference,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let struct_declaration = context.source().find_top_by_string_path(
        &reference.str_path_without_last(1),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_struct_declaration().unwrap();
    expression.resolve(match &expression.kind {
        ExpressionKind::ArgumentList(argument_list) => {
            if let Some(function) = struct_declaration.static_function(reference.str_path().last().unwrap()) {
                resolve_argument_list(
                    last_span,
                    Some(argument_list),
                    function.callable_variants(struct_declaration),
                    &struct_declaration.keywords_map(),
                    context,
                    None
                );
                let map = calculate_generics_map(struct_declaration.generics_declaration.as_ref(), types);
                TypeAndValue::type_only(function.return_type.resolved().replace_generics(&map))
            } else {
                context.insert_diagnostics_error(expression.span(), "struct static function not found");
                TypeAndValue::undetermined()
            }
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    })
}

fn resolve_struct_instance_function_reference_for_unit<'a>(
    last_span: Span,
    reference: &Reference,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let struct_declaration = context.source().find_top_by_string_path(
        &reference.str_path_without_last(1),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_struct_declaration().unwrap();
    expression.resolve(match &expression.kind {
        ExpressionKind::ArgumentList(argument_list) => {
            if let Some(function) = struct_declaration.instance_function(reference.str_path().last().unwrap()) {
                resolve_argument_list(
                    last_span,
                    Some(argument_list),
                    function.callable_variants(struct_declaration),
                    &struct_declaration.keywords_map(),
                    context,
                    None
                );
                let map = calculate_generics_map(struct_declaration.generics_declaration.as_ref(), types);
                TypeAndValue::type_only(function.return_type.resolved().replace_generics(&map))
            } else {
                context.insert_diagnostics_error(expression.span(), "struct instance function not found");
                TypeAndValue::undetermined()
            }
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    })
}

fn resolve_middleware_reference_for_unit<'a>(
    last_span: Span,
    reference: &Reference,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> TypeAndValue {
    let middleware_declaration = context.source().find_top_by_string_path(
        &reference.str_path_without_last(1),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_middleware_declaration().unwrap();
    expression.resolve(expression.resolve(match &expression.kind {
        ExpressionKind::ArgumentList(argument_list) => {
            resolve_argument_list(
                last_span,
                Some(argument_list),
                middleware_declaration.callable_variants(),
                &btreemap! {},
                context,
                None
            );
            TypeAndValue::type_only(Type::Middleware)
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    }))
}

fn resolve_namespace_reference_for_unit(
    string_path: &Vec<String>,
    expression: &Expression,
    context: &ResolverContext,
) -> TypeAndValue {
    expression.resolve(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            let mut names: Vec<&str> = string_path.iter().map(AsRef::as_ref).collect();
            names.push(identifier.name());
            if let Some(result) = search_identifier_path_names_with_filter_to_type_and_value(
                &names,
                context.schema,
                context.source(),
                &context.current_namespace().map_or(vec![], |n| n.str_path()),
                &top_filter_for_reference_type(ReferenceSpace::Default),
                context.current_availability(),
            ) {
                result
            } else {
                context.insert_diagnostics_error(expression.span(), "identifier not found");
                TypeAndValue::undetermined()
            }
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            TypeAndValue::undetermined()
        }
    })
}