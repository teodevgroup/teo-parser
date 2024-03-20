use std::collections::BTreeMap;
use maplit::btreemap;
use crate::value::option_variant::OptionVariant;
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::span::Span;
use crate::ast::unit::Unit;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::reference::Reference;
use crate::resolver::resolve_argument_list::{resolve_argument_list};
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::{Resolve, ResolveAndClone};
use crate::utils::top_filter::top_filter_for_reference_type;
use crate::expr::{ExprInfo, ReferenceInfo, ReferenceType};
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::resolver::resolve_identifier::{resolve_identifier_path_names_with_filter_to_expr_info, resolve_identifier_path_names_with_filter_to_top};
use crate::value::interface_enum_variant::InterfaceEnumVariant;
use crate::value::Value;

pub(super) fn resolve_unit<'a>(
    unit: &'a Unit,
    context: &'a ResolverContext<'a>,
    expected: &Type,
    keywords_map: &BTreeMap<Keyword, Type>,
) -> ExprInfo {
    if let Some(empty_dot) = unit.empty_dot() {
        if unit.expressions().count() == 0 {
            context.insert_diagnostics_error(empty_dot.span, "empty enum variant literal");
        } else {
            context.insert_diagnostics_error(empty_dot.span, "empty reference");
        }
    }
    if unit.expressions.len() == 1 {
        return unit_type_coerce(
            unit.expression_at(0).unwrap().span(),
            &resolve_expression(unit.expression_at(0).unwrap(), context, expected, keywords_map),
            expected,
            context
        );
    }
    let mut current: Option<ExprInfo> = None;
    for (index, expression) in unit.expressions().enumerate() {
        if current.is_some() && current.as_ref().unwrap().is_undetermined_anyway() {
            expression.resolve(ExprInfo::undetermined());
        } else {
            current = Some(resolve_current_item_for_unit(
                if index == 0 { None } else { Some(unit.expression_at(index - 1).unwrap().span()) },
                current.as_ref(),
                expression,
                context,
                keywords_map
            ));
        }
    }
    if let Some(current) = current {
        unit_type_coerce(unit.last_expression().unwrap().span(), &current, expected, context)
    } else {
        ExprInfo::undetermined()
    }
}

fn resolve_current_item_for_unit<'a>(
    last_span: Option<Span>,
    current: Option<&ExprInfo>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
    keywords_map: &BTreeMap<Keyword, Type>,
) -> ExprInfo {
    let expected = Type::Undetermined;
    if let Some(current) = current {
        if let Some(reference_info) = current.reference_info() {
            match reference_info.r#type() {
                ReferenceType::Config => resolve_config_reference_for_unit(reference_info.reference(), expression, context),
                ReferenceType::DictionaryField => resolve_current_item_type_for_unit(last_span, current, expression, context, keywords_map),
                ReferenceType::Constant => resolve_current_item_type_for_unit(last_span, current, expression, context, keywords_map),
                ReferenceType::Enum => resolve_enum_reference_for_unit(reference_info.reference(), expression, context),
                ReferenceType::EnumMember => resolve_current_item_type_for_unit(last_span, current, expression, context, keywords_map),
                ReferenceType::Model => resolve_model_reference_for_unit(reference_info.reference(), expression, context),
                ReferenceType::ModelField => ExprInfo::undetermined(),
                ReferenceType::Interface => resolve_interface_reference_for_unit(reference_info.reference(), reference_info.generics().unwrap_or(&vec![]), expression, context),
                ReferenceType::InterfaceField => ExprInfo::undetermined(),
                ReferenceType::Middleware => resolve_middleware_reference_for_unit(last_span.unwrap(), reference_info.reference(), expression, context),
                ReferenceType::DataSet => ExprInfo::undetermined(),
                ReferenceType::DecoratorDeclaration => ExprInfo::undetermined(),
                ReferenceType::PipelineItemDeclaration => ExprInfo::undetermined(),
                ReferenceType::StructDeclaration => resolve_struct_reference_for_unit(last_span.unwrap(), reference_info.reference(), reference_info.generics().unwrap_or(&vec![]), expression, context),
                ReferenceType::StructStaticFunction => resolve_struct_static_function_reference_for_unit(last_span.unwrap(), reference_info.reference(), reference_info.generics().unwrap_or(&vec![]), expression, context),
                ReferenceType::StructInstanceFunction => resolve_struct_instance_function_reference_for_unit(last_span.unwrap(), reference_info.reference(), reference_info.generics().unwrap_or(&vec![]), expression, context),
                ReferenceType::FunctionDeclaration => todo!(),
                ReferenceType::DataSetRecord => todo!(),
                ReferenceType::Namespace => resolve_namespace_reference_for_unit(reference_info.reference().string_path(), expression, context),
                ReferenceType::DeclaredSynthesizedShape => todo!(),
            }
        } else {
            resolve_current_item_type_for_unit(last_span, current, expression, context, keywords_map)
        }
    } else {
        resolve_expression(expression, context, &expected, keywords_map)
    }
}

fn resolve_current_item_type_for_unit<'a>(
    last_span: Option<Span>,
    current: &ExprInfo,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
    keywords_map: &BTreeMap<Keyword, Type>,
) -> ExprInfo {
    match current.r#type() {
        Type::Optional(inner) => {
            context.insert_diagnostics_error(expression.span(), "expression might be null");
            resolve_current_item_for_unit(last_span, Some(&current.type_altered(inner.as_ref().clone())), expression, context, keywords_map)
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
        Type::EnumVariant(_) => resolve_enum_variant_for_unit(last_span.unwrap(), current, expression, context),
        Type::InterfaceObject(reference, types) => resolve_interface_object_for_unit(reference, current, types, expression, context),
        Type::SynthesizedShape(synthesized_shape) => resolve_synthesized_shape_for_unit(synthesized_shape, current.value(), expression, context),
        Type::SynthesizedShapeReference(synthesized_shape_reference) => if let Some(definition) = synthesized_shape_reference.fetch_synthesized_definition(context.schema) {
            if let Some(synthesized_shape) = definition.as_synthesized_shape() {
                resolve_synthesized_shape_for_unit(synthesized_shape, current.value(), expression, context)
            } else {
                ExprInfo::undetermined()
            }
        } else {
            ExprInfo::undetermined()
        }
        Type::StructObject(reference, types) => resolve_struct_instance_for_unit(&reference.str_path(), &types.iter().collect(), current, last_span, expression, context, keywords_map),
        _ => ExprInfo::undetermined(),
    }
}

fn resolve_builtin_struct_instance_for_unit<'a>(
    struct_name: &str,
    gens: &Vec<&Type>,
    current: &ExprInfo,
    last_span: Option<Span>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
    keywords_map: &BTreeMap<Keyword, Type>,
) -> ExprInfo {
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
    current: &ExprInfo,
    last_span: Option<Span>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
    _keywords_map: &BTreeMap<Keyword, Type>,
) -> ExprInfo {
    let Some(struct_definition) = resolve_identifier_path_names_with_filter_to_top(
        &struct_path,
        context.schema,
        context.source(),
        &context.current_namespace_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).map(|top| top.as_struct_declaration()).flatten() else {
        context.insert_diagnostics_error(if let Some(last_span) = last_span {
            last_span
        } else {
            expression.span()
        }, "undefined struct");
        return expression.resolve_and_return(ExprInfo::undetermined());
    };
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            let Some(instance_function) = struct_definition.instance_function(identifier.name()) else {
                context.insert_diagnostics_error(expression.span(), "undefined instance function");
                return expression.resolve_and_return(ExprInfo::undetermined());
            };
            ExprInfo {
                r#type: Type::Undetermined,
                value: None,
                reference_info: Some(ReferenceInfo::new(
                    ReferenceType::StructInstanceFunction,
                    Reference::new(instance_function.path.clone(), instance_function.string_path.clone()),
                    Some(gens.iter().map(Clone::clone).map(Clone::clone).collect()))
                ),
            }
        },
        ExpressionKind::Subscript(subscript) => {
            let Some(subscript_function) = struct_definition.instance_function("subscript") else {
                context.insert_diagnostics_error(expression.span(), format!("{} is not subscriptable", current.r#type()));
                return expression.resolve_and_return(ExprInfo::undetermined());
            };
            let argument_list_declaration = subscript_function.argument_list_declaration();
            if argument_list_declaration.argument_declarations.len() != 1 {
                return expression.resolve_and_return(ExprInfo::undetermined());
            }
            let mut map = if let Some(generics_declaration) = struct_definition.generics_declaration() {
                generics_declaration.calculate_generics_map(&current.r#type.generic_types())
            } else {
                btreemap! {}
            };
            let argument_declaration = argument_list_declaration.argument_declarations().next().unwrap();
            let expected_type = argument_declaration.type_expr().resolved().replace_generics(&map);
            resolve_expression(subscript.expression(), context, &Type::Undetermined, &btreemap! {});
            if expected_type.is_generic_item() {
                map.insert(expected_type.as_generic_item().unwrap().to_string(), subscript.expression().resolved().r#type.clone());
            } else {
                if !expected_type.test(subscript.expression().resolved().r#type()) {
                    context.insert_diagnostics_error(subscript.expression().span(), format!("expect {}, found {}", expected_type, subscript.expression().resolved().r#type()));
                }
            }
            let return_type = subscript_function.return_type().resolved().replace_generics(&map);
            ExprInfo::type_only(return_type)
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        },
    })
}

fn resolve_tuple_for_unit<'a>(
    types: &Vec<Type>,
    current: &ExprInfo,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::IntSubscript(int_subscript) => {
            if int_subscript.index >= types.len() {
                context.insert_diagnostics_error(expression.span(), "index out of bounds");
                ExprInfo::undetermined()
            } else {
                let t = types.get(int_subscript.index).unwrap().clone();
                let v = if let Some(v) = &current.value {
                    v.as_tuple().map(|t| t.get(int_subscript.index)).flatten().cloned()
                } else {
                    None
                };
                ExprInfo::new(t, v, None)
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        },
    })
}

fn resolve_enum_reference_for_unit<'a>(
    reference: &Reference,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let enum_declaration = resolve_identifier_path_names_with_filter_to_top(
        &reference.str_path(),
        context.schema,
        context.source(),
        &context.current_namespace_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_enum().unwrap();
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(m) = enum_declaration.members().find(|m| m.identifier().name() == identifier.name()) {
                ExprInfo::new(Type::EnumVariant(reference.clone()), Some(if enum_declaration.option {
                    Value::OptionVariant(OptionVariant {
                        value: m.resolved().as_int().unwrap(),
                        display: format!(".{}", identifier.name()),
                    })
                } else {
                    Value::String(identifier.name().to_owned())
                }), Some(ReferenceInfo::new(
                    ReferenceType::EnumMember,
                    Reference::new(m.path.clone(), m.string_path.clone()),
                    None,
                )))
            } else {
                context.insert_diagnostics_error(expression.span(), "enum member not found");
                ExprInfo::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        },
    })
}

fn resolve_enum_variant_for_unit<'a>(
    last_span: Span,
    current: &ExprInfo,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let enum_declaration = context.source().find_node_by_string_path(
        &current.r#type.as_enum_variant().unwrap().str_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_enum().unwrap();
    if enum_declaration.interface {
        let Some(value) = current.value().map(|v| v.as_interface_enum_variant()).flatten() else {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            return expression.resolve_and_return(ExprInfo::undetermined());
        };
        let member_declaration = enum_declaration.members().find(|m| m.identifier().name() == value.value.as_str()).unwrap();
        if let Some(_) = member_declaration.argument_list_declaration() {
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
                    let args = argument_list.arguments().map(|argument| {
                        Some((argument.resolved_name()?.to_string(), argument.value().resolved().value.clone()?))
                    }).collect::<Option<BTreeMap<String, Value>>>();
                    expression.resolve_and_return(ExprInfo::new(current.r#type.clone(), args.map(|args| Value::InterfaceEnumVariant(InterfaceEnumVariant {
                        value: value.value.clone(),
                        args: Some(args),
                    })), current.reference_info().cloned()))
                },
                _ => {
                    context.insert_diagnostics_error(expression.span(), "invalid expression");
                    return expression.resolve_and_return(ExprInfo::undetermined());
                }
            }
        } else {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            return expression.resolve_and_return(ExprInfo::undetermined());
        }
    } else {
        let Some(value) = current.value().map(|v| v.as_str()).flatten() else {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            return expression.resolve_and_return(ExprInfo::undetermined());
        };
        if enum_declaration.members().find(|m| m.identifier().name() == value).is_none() {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            return expression.resolve_and_return(ExprInfo::undetermined());
        }
        expression.resolve_and_return(ExprInfo::new(current.r#type.clone(), Some(Value::String(value.to_string())), current.reference_info().cloned()))
    }
}

fn resolve_config_reference_for_unit<'a>(
    reference: &Reference,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let config = resolve_identifier_path_names_with_filter_to_top(
        &reference.str_path(),
        context.schema,
        context.source(),
        &context.current_namespace_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_config().unwrap();
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(item) = config.items().iter().find(|item| item.0.named_key_without_resolving() == Some(identifier.name())) {
                item.1.resolved().clone()
            } else {
                context.insert_diagnostics_error(expression.span(), "config item not found");
                ExprInfo::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn resolve_model_reference_for_unit<'a>(
    reference: &Reference,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let model = resolve_identifier_path_names_with_filter_to_top(
        &reference.str_path(),
        context.schema,
        context.source(),
        &context.current_namespace_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_model().unwrap();
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(item) = model.fields().find(|item| item.identifier().name() == identifier.name()) {
                ExprInfo {
                    r#type: Type::Undetermined,
                    value: None,
                    reference_info: Some(ReferenceInfo::new(
                        ReferenceType::ModelField,
                        Reference::new(item.path.clone(), item.string_path.clone()),
                        None
                    ))
                }
            } else {
                context.insert_diagnostics_error(expression.span(), "model field not found");
                ExprInfo::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn resolve_interface_reference_for_unit<'a>(
    reference: &Reference,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let interface = resolve_identifier_path_names_with_filter_to_top(
        &reference.str_path(),
        context.schema,
        context.source(),
        &context.current_namespace_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_interface_declaration().unwrap();
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(item) = interface.fields().find(|item| item.identifier().name() == identifier.name()) {
                ExprInfo {
                    r#type: Type::Undetermined,
                    value: None,
                    reference_info: Some(ReferenceInfo::new(
                        ReferenceType::InterfaceField,
                        Reference::new(item.path.clone(), item.string_path.clone()),
                        Some(types.clone()),
                    ))
                }
            } else {
                context.insert_diagnostics_error(expression.span(), "interface field not found");
                ExprInfo::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn resolve_interface_object_for_unit<'a>(
    reference: &Reference,
    current: &ExprInfo,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let interface = resolve_identifier_path_names_with_filter_to_top(
        &reference.str_path(),
        context.schema,
        context.source(),
        &context.current_namespace_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_interface_declaration().unwrap();
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some((_, t)) = interface.resolved().shape().iter().find(|(k, t)| k.as_str() == identifier.name()) {
                let map = interface.calculate_generics_map(types);
                ExprInfo::new(
                    t.replace_generics(&map),
                    current.value().map(|value| value.as_dictionary().map(|d| d.get(&identifier.name).cloned())).flatten().flatten(),
                    None,
                )
            } else {
                context.insert_diagnostics_error(expression.span(), "interface field not found");
                ExprInfo::undetermined()
            }
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn resolve_struct_reference_for_unit<'a>(
    last_span: Span,
    reference: &Reference,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let struct_declaration = resolve_identifier_path_names_with_filter_to_top(
        &reference.str_path(),
        context.schema,
        context.source(),
        &context.current_namespace_path(),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_struct_declaration().unwrap();
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            if let Some(function) = struct_declaration.static_function(identifier.name()) {
                ExprInfo::new(Type::Undetermined, None, Some(ReferenceInfo::new(
                    ReferenceType::StructStaticFunction,
                    Reference::new(function.path.clone(), function.string_path.clone()),
                    Some(types.clone())
                )))
            } else {
                context.insert_diagnostics_error(expression.span(), "struct static function not found");
                ExprInfo::undetermined()
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
                ExprInfo::type_only(Type::StructObject(Reference::new(struct_declaration.path.clone(), struct_declaration.string_path.clone()), types.clone()).flatten_struct_into_primitive())
            } else {
                context.insert_diagnostics_error(expression.span(), "struct initializer not found");
                ExprInfo::undetermined()
            }
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn resolve_struct_static_function_reference_for_unit<'a>(
    last_span: Span,
    reference: &Reference,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let struct_declaration = context.source().find_node_by_string_path(
        &reference.str_path_without_last(1),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_struct_declaration().unwrap();
    expression.resolve_and_return(match &expression.kind {
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
                let map = if let Some(generics_declaration) = struct_declaration.generics_declaration() {
                    generics_declaration.calculate_generics_map(types)
                } else {
                    btreemap! {}
                };
                ExprInfo::type_only(function.return_type().resolved().replace_generics(&map))
            } else {
                context.insert_diagnostics_error(expression.span(), "struct static function not found");
                ExprInfo::undetermined()
            }
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn resolve_struct_instance_function_reference_for_unit<'a>(
    last_span: Span,
    reference: &Reference,
    types: &Vec<Type>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let struct_declaration = context.source().find_node_by_string_path(
        &reference.str_path_without_last(1),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_struct_declaration().unwrap();
    expression.resolve_and_return(match &expression.kind {
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
                let map = if let Some(generics_declaration) = struct_declaration.generics_declaration() {
                    generics_declaration.calculate_generics_map(types)
                } else {
                    btreemap! {}
                };
                ExprInfo::type_only(function.return_type().resolved().replace_generics(&map))
            } else {
                context.insert_diagnostics_error(expression.span(), "struct instance function not found");
                ExprInfo::undetermined()
            }
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn resolve_middleware_reference_for_unit<'a>(
    last_span: Span,
    reference: &Reference,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    let middleware_declaration = context.source().find_node_by_string_path(
        &reference.str_path_without_last(1),
        &top_filter_for_reference_type(ReferenceSpace::Default),
        context.current_availability()
    ).unwrap().as_middleware_declaration().unwrap();
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::ArgumentList(argument_list) => {
            resolve_argument_list(
                last_span,
                Some(argument_list),
                middleware_declaration.callable_variants(),
                &btreemap! {},
                context,
                None
            );
            ExprInfo::type_only(Type::Middleware)
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn resolve_namespace_reference_for_unit<'a>(
    string_path: &Vec<String>,
    expression: &Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            let mut names: Vec<&str> = string_path.iter().map(AsRef::as_ref).collect();
            names.push(identifier.name());
            if let Some(result) = resolve_identifier_path_names_with_filter_to_expr_info(
                &names,
                context.schema,
                context.source(),
                &context.current_namespace().map_or(vec![], |n| n.str_path()),
                &top_filter_for_reference_type(ReferenceSpace::Default),
                context.current_availability(),
                context,
            ) {
                result
            } else {
                context.insert_diagnostics_error(expression.span(), "identifier not found");
                ExprInfo::undetermined()
            }
        }
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn unit_type_coerce<'a>(expression_span: Span, resolved: &ExprInfo, expected: &Type, context: &'a ResolverContext<'a>) -> ExprInfo {
    if expected.unwrap_optional().unwrap_enumerable().unwrap_optional().is_synthesized_enum_reference() && resolved.reference_info.is_some() && resolved.reference_info().unwrap().r#type() == ReferenceType::ModelField {
        let synthesized_enum_reference = expected.unwrap_optional().unwrap_enumerable().unwrap_optional().as_synthesized_enum_reference().unwrap();
        let model_path = resolved.reference_info().unwrap().reference.path_without_last(1);
        let field_name = *resolved.reference_info().unwrap().reference.str_path().last().unwrap();
        let model = context.schema.find_top_by_path(&model_path).unwrap().as_model().unwrap();
        if let Some(target_model_reference) = synthesized_enum_reference.owner.as_model_object() {
            if target_model_reference.path() == &model_path {
                let definition = synthesized_enum_reference.fetch_synthesized_definition(context.schema).unwrap();
                if definition.keys.contains(&field_name.to_owned()) {
                    return ExprInfo {
                        r#type: expected.unwrap_optional().unwrap_enumerable().unwrap_optional().clone(),
                        value: Some(Value::String(field_name.to_owned())),
                        reference_info: resolved.reference_info.clone()
                    };
                } else {
                    context.insert_diagnostics_error(expression_span, format!("expect {}, found other fields", synthesized_enum_reference));
                    return resolved.clone();
                }
            } else {
                context.insert_diagnostics_error(expression_span, format!("expect {}, found fields of {}", synthesized_enum_reference, model.name()));
                return resolved.clone();
            }
        }
    }
    if expected.test(resolved.r#type()) {
        resolved.clone()
    } else {
        if resolved.r#type().can_coerce_to(expected, context.schema) {
            ExprInfo {
                r#type: expected.clone(),
                value: if let Some(value) = resolved.value() {
                    resolved.r#type().coerce_value_to(value, expected)
                } else {
                    None
                },
                reference_info: resolved.reference_info().cloned()
            }
        } else {
            resolved.clone()
        }
    }
}

fn resolve_synthesized_shape_for_unit<'a>(
    synthesized_shape: &SynthesizedShape,
    value: Option<&Value>,
    expression: &'a Expression,
    context: &'a ResolverContext<'a>,
) -> ExprInfo {
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::Identifier(identifier) => {
            resolve_synthesized_shape_result_for_unit(context, identifier.span(), synthesized_shape, identifier.name(), value)
        },
        ExpressionKind::Subscript(subscript) => {
            resolve_expression(subscript.expression(), context, &Type::String, &btreemap! {});
            if !subscript.expression().resolved().r#type().is_string() {
                context.insert_diagnostics_error(subscript.expression().span(), "expect string key");
            }
            if subscript.expression().resolved().value().is_none() {
                context.insert_diagnostics_error(subscript.expression().span(), "cannot infer object key");
            }
            resolve_synthesized_shape_result_for_unit(context, subscript.expression().span(), synthesized_shape, subscript.expression().resolved().value().unwrap().as_str().unwrap(), value)
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "invalid expression");
            ExprInfo::undetermined()
        }
    })
}

fn resolve_synthesized_shape_result_for_unit<'a>(context: &'a ResolverContext<'a>, span: Span, synthesized_shape: &SynthesizedShape, name: &str, value: Option<&Value>) -> ExprInfo {
    if let Some(field) = synthesized_shape.get(name) {
        ExprInfo {
            r#type: field.clone(),
            value: if let Some(value) = value {
                value.as_dictionary().map(|d| d.get(name)).flatten().cloned()
            } else {
                None
            },
            reference_info: None
        }
    } else {
        context.insert_diagnostics_error(span, "identifier not found");
        ExprInfo::undetermined()
    }
}