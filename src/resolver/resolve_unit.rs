use std::collections::BTreeMap;
use maplit::btreemap;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::expression::{Expression, ExpressionKind, ExpressionResolved};
use crate::ast::literals::EnumVariantLiteral;
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::ast::unit::Unit;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_argument_list::{resolve_argument_list};
use crate::resolver::resolve_constant::resolve_constant;
use crate::resolver::resolve_expression::{resolve_enum_variant_literal, resolve_expression};
use crate::resolver::resolve_identifier::resolve_identifier;
use crate::resolver::resolver_context::ResolverContext;
use crate::utils::top_filter::top_filter_for_reference_type;

#[derive(Debug)]
pub(super) enum UnitResolveResult {
    Reference(Vec<usize>),
    Type(Type),
}

impl UnitResolveResult {

    pub(super) fn is_reference(&self) -> bool {
        self.as_reference().is_some()
    }

    pub(super) fn as_reference(&self) -> Option<&Vec<usize>> {
        match self {
            Self::Reference(r) => Some(r),
            _ => None,
        }
    }

    pub(super) fn is_type(&self) -> bool {
        self.as_type().is_some()
    }

    pub(super) fn as_type(&self) -> Option<&Type> {
        match self {
            Self::Type(t) => Some(t),
            _ => None,
        }
    }

    pub(super) fn is_undetermined(&self) -> bool {
        self.is_type() && self.as_type().unwrap().is_undetermined()
    }

    pub(super) fn into_type<'a>(self, context: &'a ResolverContext<'a>) -> Type {
        match self {
            Self::Type(t) => t,
            Self::Reference(path) => {
                let top = context.schema.find_top_by_path(&path).unwrap();
                if top.is_model() {
                    Type::Model
                } else if top.is_data_set() {
                    Type::DataSet
                } else {
                    Type::Undetermined
                }
            }
        }
    }
}

pub(super) fn resolve_unit<'a>(unit: &'a Unit, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, &Type>,) -> ExpressionResolved {
    if unit.expressions.len() == 1 {
        resolve_expression(unit.expressions.get(0).unwrap(), context, expected, keywords_map)
    } else {
        let first_expression = unit.expressions.get(0).unwrap();
        let expected = Type::Undetermined;
        let mut current = if let Some(identifier) = first_expression.kind.as_identifier() {
            if let Some(reference) = resolve_identifier(identifier, context, ReferenceType::Default, context.current_availability()) {
                let top = context.schema.find_top_by_path(&reference).unwrap();
                if let Some(constant) = top.as_constant() {
                    if !constant.is_resolved() {
                        resolve_constant(constant, context);
                    }
                    UnitResolveResult::Type(constant.resolved().r#type.clone())
                } else {
                    UnitResolveResult::Reference(reference)
                }
            } else {
                context.insert_diagnostics_error(identifier.span, "reference is not found");
                UnitResolveResult::Type(Type::Undetermined)
            }
        } else {
            UnitResolveResult::Type(resolve_expression(first_expression, context, &expected, keywords_map))
        };
        if current.is_undetermined() {
            return current.as_type().unwrap().clone();
        } else {
            for (index, item) in unit.expressions.iter().enumerate() {
                if index == 0 { continue }
                current = resolve_current_item_for_unit(unit.expressions.get(index - 1).unwrap().span(), &current, item, context);
            }
        }
        current.into_type(context)
    }
}

fn resolve_current_item_for_unit<'a>(last_span: Span, current: &UnitResolveResult, item: &'a Expression, context: &'a ResolverContext<'a>) -> UnitResolveResult {
    match current {
        UnitResolveResult::Type(current_value) => {
            if let Some((path, _)) = current_value.as_struct_object() {
                match &item.kind {
                    ExpressionKind::Identifier(_) => {
                        context.insert_diagnostics_error(item.span(), "Builtin instance fields and methods are not implemented yet");
                        UnitResolveResult::Type(Type::Undetermined)
                    }
                    ExpressionKind::Call(call) => {
                        let struct_declaration = context.schema.find_top_by_path(path).unwrap().as_struct_declaration().unwrap();
                        let struct_object = Type::StructObject(struct_declaration.path.clone(), struct_declaration.string_path.clone());
                        if let Some(new) = struct_declaration.function_declarations.iter().find(|f| !f.r#static && f.identifier.name() == call.identifier.name()) {
                            resolve_argument_list(last_span, Some(&call.argument_list), new.callable_variants(struct_declaration), &btreemap!{
                                Keyword::SelfIdentifier => &struct_object,
                            }, context, None);
                            UnitResolveResult::Type(new.return_type.resolved().clone())
                        } else {
                            context.insert_diagnostics_error(last_span, "struct function is not found");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                    }
                    ExpressionKind::Subscript(subscript) => {
                        let struct_declaration = context.schema.find_top_by_path(path).unwrap().as_struct_declaration().unwrap();
                        let struct_object = Type::StructObject(struct_declaration.path.clone(), struct_declaration.string_path.clone());
                        if let Some(subscript_function) = struct_declaration.function_declarations.iter().find(|f| !f.r#static && f.identifier.name() == "subscript") {
                            let resolve_result = resolve_expression(
                                subscript.expression.as_ref(),
                                context,
                                subscript_function.return_type.resolved(),
                                &btreemap!{
                                    Keyword::SelfIdentifier => &struct_object,
                                },
                            );
                            if let Some(argument_list_declaration) = &subscript_function.argument_list_declaration {
                                if let Some(argument_declaration) = argument_list_declaration.argument_declarations.first() {
                                    if argument_declaration.type_expr.resolved().test(&resolve_result) {

                                    } else {
                                        context.insert_diagnostics_error(subscript.expression.span(), format!("expect {}, found {}", argument_declaration.type_expr.resolved(), resolve_result))
                                    }
                                } else {
                                    context.insert_diagnostics_error(subscript.span, "invalid subscript function declaration")
                                }
                            } else {
                                context.insert_diagnostics_error(subscript.span, "invalid subscript function declaration")
                            }
                            UnitResolveResult::Type(subscript_function.return_type.resolved().clone())
                        } else {
                            context.insert_diagnostics_error(subscript.span, "cannot subscript");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                    }
                    _ => unreachable!(),
                }
            } else {
                context.insert_diagnostics_error(last_span, "This feature is not implemented yet");
                return UnitResolveResult::Type(Type::Undetermined)
            }
        }
        UnitResolveResult::Reference(path) => {
            match context.schema.find_top_by_path(path).unwrap() {
                Top::StructDeclaration(struct_declaration) => {
                    let struct_object = Type::StructObject(struct_declaration.path.clone(), struct_declaration.string_path.clone());
                    match &item.kind {
                        ExpressionKind::ArgumentList(argument_list) => {
                            if let Some(new) = struct_declaration.function_declarations.iter().find(|f| f.r#static && f.identifier.name() == "new") {
                                resolve_argument_list(last_span, Some(argument_list), new.callable_variants(struct_declaration), &btreemap!{
                                    Keyword::SelfIdentifier => &struct_object,
                                },  context, None);
                                UnitResolveResult::Type(new.return_type.resolved().clone())
                            } else {
                                context.insert_diagnostics_error(last_span, "Constructor is not found");
                                return UnitResolveResult::Type(Type::Undetermined)
                            }
                        }
                        ExpressionKind::Call(call) => {
                            if let Some(new) = struct_declaration.function_declarations.iter().find(|f| f.r#static && f.identifier.name() == call.identifier.name()) {
                                resolve_argument_list(last_span, Some(&call.argument_list), new.callable_variants(struct_declaration),  &btreemap!{
                                    Keyword::SelfIdentifier => &struct_object,
                                }, context, None);
                                UnitResolveResult::Type(new.return_type.resolved().clone())
                            } else {
                                context.insert_diagnostics_error(last_span, "static struct function is not found");
                                return UnitResolveResult::Type(Type::Undetermined)
                            }
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Struct cannot be subscript");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        ExpressionKind::Identifier(i) => {
                            context.insert_diagnostics_error(i.span, "Struct fields are not accessible");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                },
                Top::Config(config) => {
                    match &item.kind {
                        ExpressionKind::Identifier(identifier) => {
                            if let Some(item) = config.items.iter().find(|i| i.identifier.name() == identifier.name()) {
                                return UnitResolveResult::Type(item.expression.resolved().clone());
                            } else {
                                context.insert_diagnostics_error(item.span(), "Undefined field");
                                return UnitResolveResult::Type(Type::Undetermined)
                            }
                        },
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Config cannot be called");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        ExpressionKind::Call(c) => {
                            context.insert_diagnostics_error(c.span, "Config cannot be called");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Config cannot be subscript");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Constant(constant) => {
                    if !constant.is_resolved() {
                        resolve_constant(constant, context);
                    }
                    UnitResolveResult::Type(constant.resolved().r#type.clone())
                }
                Top::Enum(r#enum) => {
                    match &item.kind {
                        ExpressionKind::Identifier(i) => {
                            if let Some(member_declaration) = r#enum.members.iter().find(|m| m.identifier.name() == i.name()) {
                                if member_declaration.argument_list_declaration.is_some() {
                                    context.insert_diagnostics_error(i.span, "expect argument list");
                                }
                            } else {
                                context.insert_diagnostics_error(i.span, "enum member not found");
                            }
                            return UnitResolveResult::Type(Type::EnumVariant(r#enum.path.clone(), r#enum.string_path.clone()));
                        }
                        ExpressionKind::Call(c) => {
                            if let Some(member_declaration) = r#enum.members.iter().find(|m| m.identifier.name() == c.identifier.name()) {
                                if member_declaration.argument_list_declaration.is_none() {
                                    context.insert_diagnostics_error(c.argument_list.span, "unexpected argument list");
                                } else {
                                    resolve_argument_list(
                                        c.identifier.span,
                                        Some(&c.argument_list),
                                        vec![CallableVariant {
                                            generics_declarations: vec![],
                                            argument_list_declaration: Some(member_declaration.argument_list_declaration.as_ref().unwrap()),
                                            generics_constraints: vec![],
                                            pipeline_input: None,
                                            pipeline_output: None,
                                        }],
                                        &btreemap! {},
                                        context,
                                        None,
                                    );
                                }
                            } else {
                                context.insert_diagnostics_error(c.identifier.span, "enum member not found");
                            }
                            return UnitResolveResult::Type(Type::EnumVariant(r#enum.path.clone(), r#enum.string_path.clone()));
                        }
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Enum cannot be called");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Enum cannot be subscript");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Model(_) => {
                    match &item.kind {
                        ExpressionKind::Identifier(_) => todo!("return model field enum here"),
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Model cannot be called");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        ExpressionKind::Call(c) => {
                            context.insert_diagnostics_error(c.span, "Model cannot be called");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Model cannot be subscript");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Interface(_) => {
                    match &item.kind {
                        ExpressionKind::Identifier(_) => todo!("return interface field enum here"),
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Interface cannot be called");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        ExpressionKind::Call(c) => {
                            context.insert_diagnostics_error(c.span, "Interface cannot be called");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Interface cannot be subscript");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Namespace(namespace) => {
                    match &item.kind {
                        ExpressionKind::Identifier(identifier) => {
                            if let Some(top) = namespace.find_top_by_name(identifier.name(), &top_filter_for_reference_type(ReferenceType::Default), context.current_availability()) {
                                return UnitResolveResult::Reference(top.path().clone())
                            } else {
                                context.insert_diagnostics_error(identifier.span, "Invalid reference");
                                return UnitResolveResult::Type(Type::Undetermined)
                            }
                        },
                        ExpressionKind::Call(c) => {
                            todo!("resolve and call")
                        }
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Namespace cannot be called");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Namespace cannot be subscript");
                            return UnitResolveResult::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                _ => unreachable!()
            }
        }
    }
}

