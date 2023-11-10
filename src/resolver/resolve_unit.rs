use std::collections::BTreeMap;
use maplit::btreemap;
use teo_teon::types::enum_variant::EnumVariant;
use teo_teon::Value;
use crate::ast::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::expression::{Expression, ExpressionKind, TypeAndValue};
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::ast::unit::Unit;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::reference::Reference;
use crate::resolver::resolve_argument_list::{resolve_argument_list};
use crate::resolver::resolve_constant::resolve_constant;
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolve_identifier::resolve_identifier;
use crate::resolver::resolve_interface_shapes::calculate_generics_map;
use crate::resolver::resolver_context::ResolverContext;
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
            if index == 0 { None } else { unit.expressions.get(index - 1).unwrap().span() },
            current.as_ref(),
            expression,
            context,
            keywords_map
        ));
        if current.unwrap().is_undetermined() {
            return current.unwrap();
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
            Type::EnumReference(_) => {}
            Type::EnumVariant(_) => {}
            Type::ConfigReference(_) => {}
            Type::ModelReference(_) => {}
            Type::InterfaceReference(_, _) => {}
            Type::InterfaceObject(_, _) => {}
            Type::StructReference(_, _) => {}
            Type::StructObject(_, _) => {}
            Type::StructStaticFunctionReference(_, _) => {}
            Type::StructInstanceFunctionReference(_, _) => {}
            Type::FunctionReference(_) => {}
            Type::Middleware => {}
            Type::MiddlewareReference(_) => {}
            Type::DataSet => {}
            Type::DataSetReference(_) => {}
            Type::DataSetGroup(_) => {}
            Type::DataSetRecord(_, _) => {}
            Type::Namespace => {}
            Type::NamespaceReference(_) => {}
            Type::Pipeline(_, _) => {}
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
        &top_filter_for_reference_type(ReferenceType::Default),
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
                TypeAndValue::undetermined()
            };
            TypeAndValue::type_only(Type::StructInstanceFunctionReference(Reference::new(instance_function.path.clone(), instance_function.string_path.clone()), gens.iter().cloned().collect()))
        },
        ExpressionKind::Subscript(subscript) => {
            let Some(subscript_function) = struct_definition.instance_function("subscript") else {
                context.insert_diagnostics_error(expression.span(), format!("{} is not subscriptable", current.r#type()));
                TypeAndValue::undetermined()
            };
            let Some(argument_list_declaration) = subscript_function.argument_list_declaration.as_ref() else {
                TypeAndValue::undetermined()
            };
            if argument_list_declaration.argument_declarations.len() != 1 {
                return expression.resolve(TypeAndValue::undetermined());
            }
            let mut map = calculate_generics_map(struct_definition.generics_declaration.as_ref(), &current.r#type.generic_types());
            let argument_declaration = argument_list_declaration.argument_declarations.first().unwrap();
            let expected_type = argument_declaration.type_expr.resolved().replace_generics(&map);
            resolve_expression(subscript.expression.as_ref(), context, &Type::Undetermined, &btreemap! {});
            if expected_type.is_generic_item() {
                map.insert(expected_type.as_generic_item().unwrap().into_string(), subscript.expression.resolved().r#type.clone());
            } else {
                if !expected_type.test(subscript.expression.resolved().r#type()) {
                    context.insert_diagnostics_error(subscript.expression.span(), format!("expect {}, found {}", expected_type, subscript.expression.resolved().r#type()));
                }
            }
            let return_type = subscript_function.return_type.resolved().replace_generics(&map);
            TypeAndValue::type_only(return_type)
        },
        _ => TypeAndValue::undetermined(),
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
        _ => TypeAndValue::undetermined(),
    })
}

// match current {
//
// UnitResolveResult::Reference(path) => {
// match context.schema.find_top_by_path(path).unwrap() {
// Top::StructDeclaration(struct_declaration) => {
// let struct_object = Type::StructObject(struct_declaration.path.clone(), struct_declaration.string_path.clone());
// match &expression.kind {
// ExpressionKind::ArgumentList(argument_list) => {
// if let Some(new) = struct_declaration.function_declarations.iter().find(|f| f.r#static && f.identifier.name() == "new") {
// resolve_argument_list(last_span, Some(argument_list), new.callable_variants(struct_declaration), &btreemap!{
// Keyword::SelfIdentifier => &struct_object,
// },  context, None);
// UnitResolveResult::Result(TypeAndValue::type_only(new.return_type.resolved().clone()))
// } else {
// context.insert_diagnostics_error(last_span, "Constructor is not found");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// }
// ExpressionKind::Call(call) => {
// if let Some(new) = struct_declaration.function_declarations.iter().find(|f| f.r#static && f.identifier.name() == call.identifier.name()) {
// resolve_argument_list(last_span, Some(&call.argument_list), new.callable_variants(struct_declaration),  &btreemap!{
// Keyword::SelfIdentifier => &struct_object,
// }, context, None);
// UnitResolveResult::Result(TypeAndValue::type_only(new.return_type.resolved().clone()))
// } else {
// context.insert_diagnostics_error(last_span, "static struct function is not found");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// }
// ExpressionKind::Subscript(s) => {
// context.insert_diagnostics_error(s.span, "Struct cannot be subscript");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// ExpressionKind::Identifier(i) => {
// context.insert_diagnostics_error(i.span, "Struct fields are not accessible");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// _ => unreachable!()
// }
// },
// Top::Config(config) => {
// match &expression.kind {
// ExpressionKind::Identifier(identifier) => {
// if let Some(item) = config.items.iter().find(|i| i.identifier.name() == identifier.name()) {
// return UnitResolveResult::Result(item.expression.resolved().clone());
// } else {
// context.insert_diagnostics_error(expression.span(), "Undefined field");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// },
// ExpressionKind::ArgumentList(a) => {
// context.insert_diagnostics_error(a.span, "Config cannot be called");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// ExpressionKind::Call(c) => {
// context.insert_diagnostics_error(c.span, "Config cannot be called");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// ExpressionKind::Subscript(s) => {
// context.insert_diagnostics_error(s.span, "Config cannot be subscript");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// _ => unreachable!()
// }
// }
// Top::Constant(constant) => {
// if !constant.is_resolved() {
// resolve_constant(constant, context);
// }
// UnitResolveResult::Result(constant.resolved().expression_resolved.clone())
// }
// Top::Enum(r#enum) => {
// match &expression.kind {
// ExpressionKind::Identifier(i) => {
// if let Some(member_declaration) = r#enum.members.iter().find(|m| m.identifier.name() == i.name()) {
// if member_declaration.argument_list_declaration.is_some() {
// context.insert_diagnostics_error(i.span, "expect argument list");
// }
// } else {
// context.insert_diagnostics_error(i.span, "enum member not found");
// }
// return UnitResolveResult::Result(TypeAndValue {
// r#type: Type::EnumVariant(r#enum.path.clone(), r#enum.string_path.clone()),
// value: Some(Value::EnumVariant(EnumVariant {
// value: Box::new(Value::String(i.name().to_owned())),
// display: format!(".{}", i.name()),
// path: r#enum.string_path.clone(),
// args: None,
// })),
// });
// }
// ExpressionKind::Call(c) => {
// if let Some(member_declaration) = r#enum.members.iter().find(|m| m.identifier.name() == c.identifier.name()) {
// if member_declaration.argument_list_declaration.is_none() {
// context.insert_diagnostics_error(c.argument_list.span, "unexpected argument list");
// } else {
// resolve_argument_list(
// c.identifier.span,
// Some(&c.argument_list),
// vec![CallableVariant {
// generics_declarations: vec![],
// argument_list_declaration: Some(member_declaration.argument_list_declaration.as_ref().unwrap()),
// generics_constraints: vec![],
// pipeline_input: None,
// pipeline_output: None,
// }],
// &btreemap! {},
// context,
// None,
// );
// }
// } else {
// context.insert_diagnostics_error(c.identifier.span, "enum member not found");
// }
// return UnitResolveResult::Result(TypeAndValue {
// r#type: Type::EnumVariant(r#enum.path.clone(), r#enum.string_path.clone()),
// value: Some(Value::EnumVariant(EnumVariant {
// value: Box::new(Value::String(c.identifier.name().to_owned())),
// display: format!(".{}", c.identifier.name()),
// path: r#enum.string_path.clone(),
// args: None,
// })),
// });
// }
// ExpressionKind::ArgumentList(a) => {
// context.insert_diagnostics_error(a.span, "Enum cannot be called");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// ExpressionKind::Subscript(s) => {
// context.insert_diagnostics_error(s.span, "Enum cannot be subscript");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// _ => unreachable!()
// }
// }
// Top::Model(_) => {
// match &expression.kind {
// ExpressionKind::Identifier(_) => todo!("return model field enum here"),
// ExpressionKind::ArgumentList(a) => {
// context.insert_diagnostics_error(a.span, "Model cannot be called");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// ExpressionKind::Call(c) => {
// context.insert_diagnostics_error(c.span, "Model cannot be called");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// ExpressionKind::Subscript(s) => {
// context.insert_diagnostics_error(s.span, "Model cannot be subscript");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// _ => unreachable!()
// }
// }
// Top::Interface(_) => {
// match &expression.kind {
// ExpressionKind::Identifier(_) => todo!("return interface field enum here"),
// ExpressionKind::ArgumentList(a) => {
// context.insert_diagnostics_error(a.span, "Interface cannot be called");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// ExpressionKind::Call(c) => {
// context.insert_diagnostics_error(c.span, "Interface cannot be called");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// ExpressionKind::Subscript(s) => {
// context.insert_diagnostics_error(s.span, "Interface cannot be subscript");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// _ => unreachable!()
// }
// }
// Top::Namespace(namespace) => {
// match &expression.kind {
// ExpressionKind::Identifier(identifier) => {
// if let Some(top) = namespace.find_top_by_name(identifier.name(), &top_filter_for_reference_type(ReferenceType::Default), context.current_availability()) {
// return UnitResolveResult::Reference(top.path().clone())
// } else {
// context.insert_diagnostics_error(identifier.span, "Invalid reference");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// },
// ExpressionKind::Call(c) => {
// todo!("resolve and call")
// }
// ExpressionKind::ArgumentList(a) => {
// context.insert_diagnostics_error(a.span, "Namespace cannot be called");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// ExpressionKind::Subscript(s) => {
// context.insert_diagnostics_error(s.span, "Namespace cannot be subscript");
// return UnitResolveResult::Result(TypeAndValue::undetermined())
// }
// _ => unreachable!()
// }
// }
// _ => unreachable!()
// }
// }
// }