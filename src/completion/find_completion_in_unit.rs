use array_tool::vec::Join;
use crate::ast::expression::ExpressionKind;
use crate::ast::reference_space::ReferenceSpace;
use crate::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::completion::collect_argument_list_names::collect_argument_list_names_from_argument_list_declaration;
use crate::completion::completion_item::CompletionItem;
use crate::completion::completion_item_from_top::documentation_from_comment;
use crate::completion::find_completion_in_argument_list::find_completion_in_argument_list;
use crate::completion::find_completion_in_enum_variant_literal::find_completion_in_empty_enum_variant_literal;
use crate::completion::find_completion_in_expression::find_completion_in_expression;
use crate::completion::find_top_completion_with_filter::find_top_completion_with_filter;
use crate::expr::{ExprInfo, ReferenceType};
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::r#type::Type;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn find_completion_in_unit(schema: &Schema, source: &Source, unit: &Unit, line_col: (usize, usize), namespace_path: &Vec<&str>, expect: &Type, availability: Availability) -> Vec<CompletionItem> {
    if unit.expressions().count() == 0 {
        if let Some(empty_dot) = unit.empty_dot() {
            if empty_dot.span.contains_line_col(line_col) {
                return find_completion_in_empty_enum_variant_literal(schema, source, namespace_path, &expect.expect_for_enum_variant_literal(), availability);
            }
        }
        return vec![];
    }
    let mut previous_resolved = &ExprInfo::undetermined();
    for (index, expression) in unit.expressions().enumerate() {
        if expression.span().contains_line_col(line_col) {
            if index == 0 {
                return find_completion_in_expression(
                    schema,
                    source,
                    expression,
                    line_col,
                    namespace_path,
                    expect,
                    availability,
                );
            } else {
                match &expression.kind {
                    ExpressionKind::ArgumentList(argument_list) => {
                        let mut names = vec![];
                        if let Some(reference_info) = previous_resolved.reference_info() {
                            match reference_info.r#type {
                                ReferenceType::StructInstanceFunction => {
                                    let struct_definition = schema.find_top_by_path(&reference_info.reference().path_without_last(1)).unwrap().as_struct_declaration().unwrap();
                                    let function_definition = struct_definition.instance_function(*reference_info.reference().str_path().last().unwrap()).unwrap();
                                    let argument_names = collect_argument_list_names_from_argument_list_declaration(function_definition.argument_list_declaration());
                                    names = vec![argument_names];
                                },
                                ReferenceType::StructStaticFunction => {
                                    let struct_definition = schema.find_top_by_path(&reference_info.reference().path_without_last(1)).unwrap().as_struct_declaration().unwrap();
                                    let function_definition = struct_definition.static_function(*reference_info.reference().str_path().last().unwrap()).unwrap();
                                    let argument_names = collect_argument_list_names_from_argument_list_declaration(function_definition.argument_list_declaration());
                                    names = vec![argument_names];
                                },
                                ReferenceType::EnumMember => {
                                    let enum_definition = schema.find_top_by_path(&reference_info.reference().path_without_last(1)).unwrap().as_enum().unwrap();
                                    let member_definition = enum_definition.members().find(|m| m.identifier().name() == *reference_info.reference().str_path().last().unwrap()).unwrap();
                                    if let Some(argument_list_declaration) = member_definition.argument_list_declaration() {
                                        let argument_names = collect_argument_list_names_from_argument_list_declaration(argument_list_declaration);
                                        names = vec![argument_names];
                                    }
                                },
                                _ => (),
                            }
                        }
                        return find_completion_in_argument_list(
                            schema,
                            source,
                            argument_list,
                            line_col,
                            namespace_path,
                            availability,
                            names,
                        );
                    },
                    ExpressionKind::Subscript(subscript) => if subscript.expression().span().contains_line_col(line_col) {
                        return find_completion_in_expression(schema, source, subscript.expression(), line_col, namespace_path, &Type::Undetermined, availability);
                    } else {
                        return vec![];
                    },
                    ExpressionKind::IntSubscript(_) => {
                        return if let Some(union) = previous_resolved.r#type().as_union() {
                            completion_items_from_tuple_types(union)
                        } else {
                            vec![]
                        };
                    },
                    ExpressionKind::Identifier(_) => {
                        return completion_items_in_unit_for_identifier_or_int_subscript_with_previous_resolved(
                            schema, source, previous_resolved, namespace_path, availability,
                        );
                    },
                    _ => unreachable!(),
                }
            }
        } else {
            previous_resolved = expression.resolved();
        }
    }
    if let Some(empty_dot) = unit.empty_dot() {
        if empty_dot.span.contains_line_col(line_col) {
            return completion_items_in_unit_for_identifier_or_int_subscript_with_previous_resolved(
                schema, source, previous_resolved, namespace_path, availability,
            );
        }
    }
    vec![]
}

fn completion_items_in_unit_for_identifier_or_int_subscript_with_previous_resolved(
    schema: &Schema,
    source: &Source,
    previous_resolved: &ExprInfo,
    namespace_path: &Vec<&str>,
    availability: Availability,
) -> Vec<CompletionItem> {
    if let Some(reference_info) = previous_resolved.reference_info() {
        match reference_info.r#type() {
            ReferenceType::Config => {
                let config_declaration = schema.find_top_by_path(reference_info.reference.path()).unwrap().as_config().unwrap();
                config_declaration.dictionary_literal().expressions().filter_map(|named_expression| {
                    if let Some(key) = named_expression.key().named_key_without_resolving() {
                        Some(CompletionItem {
                            label: key.to_string(),
                            namespace_path: Some(format!("{}", named_expression.value().resolved().r#type())),
                            documentation: None,
                            detail: None,
                        })
                    } else {
                        None
                    }
                }).collect()
            }
            ReferenceType::Constant => completion_items_in_unit_for_identifier_or_int_subscript_with_type(
                schema,
                source,
                previous_resolved.r#type(),
                namespace_path,
                availability,
            ),
            ReferenceType::Enum => {
                let enum_definition = schema.find_top_by_path(reference_info.reference.path()).unwrap().as_enum().unwrap();
                enum_definition.members().map(|member| CompletionItem {
                    label: member.name().to_owned(),
                    namespace_path: Some(enum_definition.str_path().join(".")),
                    documentation: documentation_from_comment(member.comment()),
                    detail: None,
                }).collect()
            }
            ReferenceType::Model => {
                let model_definition = schema.find_top_by_path(reference_info.reference.path()).unwrap().as_model().unwrap();
                model_definition.fields().map(|field| CompletionItem {
                    label: field.name().to_owned(),
                    namespace_path: Some(model_definition.str_path().join(".")),
                    documentation: documentation_from_comment(field.comment()),
                    detail: None,
                }).collect()
            }
            ReferenceType::StructDeclaration => {
                let struct_declaration = schema.find_top_by_path(reference_info.reference.path()).unwrap().as_struct_declaration().unwrap();
                struct_declaration.function_declarations().filter_map(|function| {
                    if function.r#static {
                        Some(CompletionItem {
                            label: function.identifier().name().to_owned(),
                            namespace_path: Some(struct_declaration.str_path().join(".")),
                            documentation: documentation_from_comment(function.comment()),
                            detail: None,
                        })
                    } else {
                        None
                    }
                }).collect()
            }
            ReferenceType::Namespace => {
                let user_typed_spaces = reference_info.reference().str_path();
                find_top_completion_with_filter(schema, source, namespace_path, &user_typed_spaces, &top_filter_for_reference_type(ReferenceSpace::Default), availability)
            }
            _ => vec![]
        }
    } else {
        completion_items_in_unit_for_identifier_or_int_subscript_with_type(
            schema,
            source,
            previous_resolved.r#type(),
            namespace_path,
            availability,
        )
    }
}

fn completion_items_in_unit_for_identifier_or_int_subscript_with_type(
    schema: &Schema,
    source: &Source,
    r#type: &Type,
    namespace_path: &Vec<&str>,
    availability: Availability,
) -> Vec<CompletionItem> {
    if let Some((reference, _)) = r#type.as_struct_object() {
        let struct_declaration = schema.find_top_by_path(reference.path()).unwrap().as_struct_declaration().unwrap();
        struct_declaration.function_declarations().filter_map(|function| {
            if !function.r#static {
                Some(CompletionItem {
                    label: function.identifier().name().to_owned(),
                    namespace_path: Some(struct_declaration.str_path().join(".")),
                    documentation: documentation_from_comment(function.comment()),
                    detail: None,
                })
            } else {
                None
            }
        }).collect()
    } else if let Some(tuple) = r#type.as_tuple() {
        completion_items_from_tuple_types(tuple)
    } else if let Some(synthesized_shape) = r#type.as_synthesized_shape() {
        completion_items_in_unit_for_synthesized_shape(synthesized_shape)
    } else if let Some(synthesized_shape_reference) = r#type.as_synthesized_shape_reference() {
        if let Some(definition) = synthesized_shape_reference.fetch_synthesized_definition(schema) {
            if let Some(synthesized_shape) = definition.as_synthesized_shape() {
                completion_items_in_unit_for_synthesized_shape(synthesized_shape)
            } else {
                vec![]
            }
        } else {
            vec![]
        }
    } else {
        vec![]
    }
}

fn completion_items_from_tuple_types(tuple: &Vec<Type>) -> Vec<CompletionItem> {
    tuple.iter().enumerate().map(|(idx, t)| CompletionItem {
        label: format!("{}", idx + 1),
        namespace_path: Some(format!("{t}")),
        documentation: None,
        detail: None,
    }).collect()
}

fn completion_items_in_unit_for_synthesized_shape(
    synthesized_shape: &SynthesizedShape,
) -> Vec<CompletionItem> {
    synthesized_shape.iter().map(|(k, v)| CompletionItem {
        label: k.to_string(),
        namespace_path: Some(format!("{}", v)),
        documentation: None,
        detail: None,
    }).collect()
}