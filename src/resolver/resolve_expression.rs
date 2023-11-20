use std::collections::BTreeMap;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};
use indexmap::IndexMap;
use maplit::{btreemap, hashset};
use teo_teon::types::enum_variant::EnumVariant;
use teo_teon::types::range::Range;
use teo_teon::Value;
use teo_teon::types::option_variant::OptionVariant;
use crate::ast::arith_expr::{ArithExpr, ArithExprOperator};
use crate::ast::bracket_expression::BracketExpression;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::group::Group;
use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, EnumVariantLiteral, NullLiteral, NumericLiteral, RegexLiteral, StringLiteral, TupleLiteral};
use crate::ast::reference_space::ReferenceSpace;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::synthesized_enum::SynthesizedEnum;
use crate::resolver::resolve_argument_list::resolve_argument_list;
use crate::resolver::resolve_identifier::resolve_identifier_with_diagnostic_message;
use crate::resolver::resolve_pipeline::resolve_pipeline;
use crate::resolver::resolve_unit::resolve_unit;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::has_availability::HasAvailability;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::{Resolve, ResolveAndClone};
use crate::expr::{ExprInfo, ReferenceInfo, ReferenceType};
use crate::r#type::reference::Reference;
use crate::search::search_identifier_path::{search_identifier_path_names_with_filter_to_top, search_identifier_path_names_with_filter_to_top_multiple};
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_expression<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>) -> ExprInfo {
    let t = resolve_expression_kind(&expression.kind, context, expected, keywords_map);
    expression.resolve(t.clone());
    t
}

fn resolve_expression_kind<'a>(expression: &'a ExpressionKind, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> ExprInfo {
    match &expression {
        ExpressionKind::Group(e) => resolve_group(e, context, expected, keywords_map),
        ExpressionKind::ArithExpr(e) => resolve_arith_expr(e, context, expected, keywords_map),
        ExpressionKind::NumericLiteral(n) => resolve_numeric_literal(n, context, &expected.expect_for_literal()),
        ExpressionKind::StringLiteral(e) => resolve_string_literal(e, context, &expected.expect_for_literal()),
        ExpressionKind::RegexLiteral(e) => resolve_regex_literal(e, context, &expected.expect_for_literal()),
        ExpressionKind::BoolLiteral(b) => resolve_bool_literal(b, context, &expected.expect_for_literal()),
        ExpressionKind::NullLiteral(n) => resolve_null_literal(n, context, &expected.expect_for_literal()),
        ExpressionKind::EnumVariantLiteral(e) => resolve_enum_variant_literal(e, context, &expected.expect_for_enum_variant_literal()),
        ExpressionKind::TupleLiteral(t) => resolve_tuple_literal(t, context, &expected.expect_for_literal(), keywords_map),
        ExpressionKind::ArrayLiteral(a) => resolve_array_literal(a, context, &expected.expect_for_array_literal(), keywords_map),
        ExpressionKind::DictionaryLiteral(d) => resolve_dictionary_literal(d, context, &expected.expect_for_literal(), keywords_map),
        ExpressionKind::Identifier(i) => resolve_identifier_with_diagnostic_message(i, context),
        ExpressionKind::ArgumentList(_) => unreachable!(),
        ExpressionKind::Subscript(_) => unreachable!(),
        ExpressionKind::IntSubscript(_) => unreachable!(),
        ExpressionKind::Unit(u) => resolve_unit(u, context, expected, keywords_map),
        ExpressionKind::Pipeline(p) => resolve_pipeline(p, context, expected, keywords_map),
        ExpressionKind::NamedExpression(_) => unreachable!(),
        ExpressionKind::BracketExpression(e) => resolve_bracket_expression(e, context, &Type::String, keywords_map),
    }
}

fn resolve_group<'a>(group: &'a Group, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> ExprInfo {
    resolve_expression(group.expression(), context, expected, keywords_map)
}

fn resolve_numeric_literal<'a>(n: &NumericLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> ExprInfo {
    let mut expected = expected;
    if expected.is_optional() {
        expected = expected.unwrap_optional();
    }
    let undetermined = Type::Undetermined;
    expected = if let Some(types) = expected.as_union() {
        types.iter().find_map(|t| if t.is_int_32_or_64() || t.is_float_32_or_64() {
            Some(t)
        } else {
            None
        }).unwrap_or(&undetermined)
    } else {
        &undetermined
    };
    match expected {
        Type::Undetermined => if n.value.is_int64() {
            ExprInfo {
                r#type: Type::Int64,
                value: Some(n.value.clone()),
                reference_info: None,
            }
        } else if n.value.is_int() {
            ExprInfo {
                r#type: Type::Int,
                value: Some(n.value.clone()),
                reference_info: None,
            }
        } else if n.value.is_float() {
            ExprInfo {
                r#type: Type::Float,
                value: Some(n.value.clone()),
                reference_info: None,
            }
        } else {
            unreachable!()
        },
        Type::Int => if n.value.is_any_int() {
            ExprInfo {
                r#type: Type::Int,
                value: Some(Value::Int(n.value.to_int().unwrap())),
                reference_info: None,
            }
        } else {
            context.insert_diagnostics_error(n.span, "value is not int");
            ExprInfo::undetermined()
        },
        Type::Int64 => if n.value.is_any_int() {
            ExprInfo {
                r#type: Type::Int64,
                value: Some(Value::Int64(n.value.to_int64().unwrap())),
                reference_info: None,
            }
        } else {
            context.insert_diagnostics_error(n.span, "value is not int64");
            ExprInfo::undetermined()
        },
        Type::Float32 => if n.value.is_any_float() {
            ExprInfo {
                r#type: Type::Float32,
                value: Some(Value::Float32(n.value.to_float32().unwrap())),
                reference_info: None,
            }
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            ExprInfo::undetermined()
        },
        Type::Float => if n.value.is_any_float() {
            ExprInfo {
                r#type: Type::Float,
                value: Some(Value::Float(n.value.to_float().unwrap())),
                reference_info: None,
            }
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            ExprInfo::undetermined()
        },
        _ => {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            ExprInfo::undetermined()
        }
    }
}

fn resolve_string_literal<'a>(s: &StringLiteral, _context: &'a ResolverContext<'a>, _expected: &Type) -> ExprInfo {
    ExprInfo {
        r#type: Type::String,
        value: Some(Value::String(s.value.clone())),
        reference_info: None,

    }
}

fn resolve_regex_literal<'a>(r: &RegexLiteral, _context: &'a ResolverContext<'a>, _expected: &Type) -> ExprInfo {
    ExprInfo {
        r#type: Type::Regex,
        value: Some(Value::Regex(r.value.clone())),
        reference_info: None,

    }
}

fn resolve_bool_literal<'a>(r: &BoolLiteral, _context: &'a ResolverContext<'a>, _expected: &Type) -> ExprInfo {
    ExprInfo {
        r#type: Type::Bool,
        value: Some(Value::Bool(r.value)),
        reference_info: None,

    }
}

fn resolve_null_literal<'a>(_n: &NullLiteral, _context: &'a ResolverContext<'a>, _expected: &Type) -> ExprInfo {
    ExprInfo {
        r#type: Type::Null,
        value: Some(Value::Null),
        reference_info: None,

    }
}

pub(super) fn resolve_enum_variant_literal<'a>(e: &'a EnumVariantLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> ExprInfo {
    if let Some(enum_reference) = expected.as_enum_variant() {
        let r#enum = context.schema.find_top_by_path(enum_reference.path()).unwrap().as_enum().unwrap();
        let Some(member) = r#enum.members().find(|m| m.identifier().name() == e.identifier().name()) else {
            context.insert_diagnostics_error(e.span, format!("expect {}, found .{}", enum_reference.string_path().join("."), e.identifier().name()));
            return ExprInfo {
                r#type: Type::EnumVariant(enum_reference.clone()),
                value: None,
                reference_info: None,
            }
        };
        if let Some(argument_list_declaration) = member.argument_list_declaration() {
            if let Some(argument_list) = e.argument_list() {
                resolve_argument_list(
                    e.identifier().span,
                    Some(argument_list),
                    vec![CallableVariant {
                        generics_declarations: vec![],
                        argument_list_declaration: Some(argument_list_declaration),
                        generics_constraints: vec![],
                        pipeline_input: None,
                        pipeline_output: None,
                    }],
                    &btreemap!{},
                    context,
                    None
                );
            } else {
                context.insert_diagnostics_error(e.span, format!("expect argument list"));
                return ExprInfo {
                    r#type: Type::EnumVariant(enum_reference.clone()),
                    value: None,
                    reference_info: None,
                }
            }
        }
        if r#enum.option {
            ExprInfo {
                r#type: Type::EnumVariant(enum_reference.clone()),
                value: Some(Value::OptionVariant(OptionVariant {
                    value: member.resolved().as_int().unwrap(),
                    display: format!(".{}", member.identifier().name()),
                })),
                reference_info: None,
            }
        } else {
            ExprInfo {
                r#type: Type::EnumVariant(enum_reference.clone()),
                value: Some(Value::EnumVariant(EnumVariant {
                    value: member.resolved().as_str().unwrap().to_string(),
                    args: if let Some(argument_list) = e.argument_list() {
                        let mut has_runtime_value = false;
                        let mut args = btreemap! {};
                        for argument in argument_list.arguments() {
                            if !argument.is_resolved() {
                                has_runtime_value = true;
                                break
                            }
                            if argument.value().resolved().value().is_none() {
                                has_runtime_value = true;
                                break
                            }
                            args.insert(argument.resolved_name().unwrap().to_owned(), argument.value().resolved().value().unwrap().clone());
                        }
                        if has_runtime_value { None } else { Some(args) }
                    } else {
                        None
                    },
                })),
                reference_info: None,
            }
        }
    } else if let Some(synthesized_enum) = expected.as_synthesized_enum() {
        resolve_enum_variant_literal_from_synthesized_enum(e, synthesized_enum, context, expected)
    } else if let Some(reference) = expected.as_synthesized_enum_reference() {
        if let Some(synthesized_enum) = reference.fetch_synthesized_definition(context.schema) {
            resolve_enum_variant_literal_from_synthesized_enum(e, synthesized_enum, context, expected)
        } else {
            context.insert_diagnostics_error(e.span, format!("expect {}, found .{}", reference, e.identifier().name()));
            ExprInfo {
                r#type: Type::SynthesizedEnumReference(reference.clone()),
                value: None,
                reference_info: None,
            }
        }
    } else if let Some((data_set_object, that_model)) = expected.as_data_set_record() {
        let string_path = data_set_object.as_data_set_object().unwrap();
        for data_set in search_identifier_path_names_with_filter_to_top_multiple(
            &string_path.iter().map(AsRef::as_ref).collect(),
            context.schema,
            context.source(),
            &context.current_namespace_path(),
            &top_filter_for_reference_type(ReferenceSpace::Default),
            context.current_availability(),
        ).iter().map(|n| n.as_data_set().unwrap()) {
            if let Some(group) = data_set.groups().find(|g| g.resolved().path() == that_model.as_model_object().unwrap().path()) {
                if let Some(record) = group.records().find(|r| r.identifier().name() == e.identifier().name()) {
                    return ExprInfo {
                        r#type: expected.clone(),
                        value: Some(Value::EnumVariant(EnumVariant {
                            value: e.identifier().name().to_owned(),
                            args: None,
                        })),
                        reference_info: Some(ReferenceInfo::new(ReferenceType::DataSetRecord, Reference::new(record.path.clone(), record.string_path.clone()), None)),
                    };
                }
            }
        };
        context.insert_diagnostics_error(e.span, format!("expected {}, found .{}", expected, e.identifier().name()));
        ExprInfo {
            r#type: expected.clone(),
            value: None,
            reference_info: None,
        }
    } else {
        context.insert_diagnostics_error(e.span, format!("expected {}, found .{}", expected, e.identifier().name()));
        ExprInfo {
            r#type: expected.clone(),
            value: None,
            reference_info: None,
        }
    }
}

fn resolve_enum_variant_literal_from_synthesized_enum<'a>(e: &EnumVariantLiteral, synthesized_enum: &SynthesizedEnum, context: &'a ResolverContext<'a>, source: &Type) -> ExprInfo {
    if synthesized_enum.keys.contains(&e.identifier().name) {
        ExprInfo {
            r#type: source.clone(),
            value: Some(Value::EnumVariant(EnumVariant {
                value: e.identifier().name().to_string(),
                args: None,
            })),
            reference_info: None,

        }
    } else {
        context.insert_diagnostics_error(e.span, format!("expect {}, found .{}", synthesized_enum, e.identifier().name()));
        ExprInfo {
            r#type: source.clone(),
            value: None,
            reference_info: None,
        }
    }
}

fn resolve_tuple_literal<'a>(t: &'a TupleLiteral, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> ExprInfo {
    let types = expected.as_tuple();
    let mut retval_values = vec![];
    let mut retval_type = vec![];
    let mut unresolved = false;
    let undetermined = Type::Undetermined;
    for (i, e) in t.expressions().enumerate() {
        let resolved = resolve_expression(e, context, types.map(|t| t.get(i)).flatten().unwrap_or(&undetermined), keywords_map);
        if resolved.value.is_none() {
            unresolved = true;
        } else {
            retval_values.push(resolved.value.unwrap())
        }
        retval_type.push(resolved.r#type);
    }
    ExprInfo {
        r#type: Type::Tuple(retval_type),
        value: if unresolved { None } else { Some(Value::Tuple(retval_values)) },
        reference_info: None,

    }
}

fn resolve_array_literal<'a>(a: &'a ArrayLiteral, context: &'a ResolverContext<'a>, mut expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> ExprInfo {
    if expected.is_optional() {
        expected = expected.unwrap_optional();
    }
    let undetermined = Type::Undetermined;
    let r#type = if let Some(inner) = expected.as_array() {
        inner
    } else if let Some(types) = expected.as_union() {
        types.iter().find_map(|t| if t.is_array() {
            Some(t.as_array().unwrap())
        } else {
            None
        }).unwrap_or(&undetermined)
    } else {
        &undetermined
    };
    let mut retval = hashset![];
    let mut unresolved = false;
    let mut retval_values = vec![];
    for e in a.expressions() {
        let resolved = resolve_expression(e, context, r#type, keywords_map);
        retval.insert(resolved.r#type.clone());
        if let Some(value) = resolved.value {
            retval_values.push(value);
        } else {
            unresolved = true;
        }
    }
    let new_type = if retval.len() == 2 && retval.contains(&Type::Null) {
        let t = retval.iter().find(|t| !t.is_null()).unwrap().clone();
        Type::Array(Box::new(Type::Optional(Box::new(t))))
    } else if retval.len() == 1 {
        Type::Array(Box::new(retval.iter().next().unwrap().clone()))
    } else {
        Type::Array(Box::new(Type::Union(retval.iter().map(|t| t.clone()).collect())))
    };
    ExprInfo {
        r#type: new_type,
        value: if unresolved { None } else { Some(Value::Array(retval_values)) },
        reference_info: None,

    }
}

pub(super) fn resolve_dictionary_literal<'a>(a: &'a DictionaryLiteral, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> ExprInfo {
    let undetermined = Type::Undetermined;
    let r#type = if let Some(v) = expected.as_dictionary() {
        v
    } else {
        &undetermined
    };
    let mut retval = hashset![];
    let mut retval_values = IndexMap::new();
    let mut unresolved = false;
    for named_expression in a.expressions() {
        *named_expression.actual_availability.borrow_mut() = context.current_availability();
        if named_expression.is_available() {
            let k_value = resolve_expression_for_named_expression_key(named_expression.key(), context, &Type::String, keywords_map);
            if !k_value.r#type.is_string() {
                context.insert_diagnostics_error(named_expression.key().span(), "dictionary key is not string");
            }
            let v_value = resolve_expression(named_expression.value(), context, r#type, keywords_map);
            retval.insert(v_value.r#type.clone());
            if k_value.value.is_none() || v_value.value.is_none() {
                unresolved = true;
            } else {
                retval_values.insert(k_value.value.as_ref().unwrap().as_str().unwrap().to_owned(), v_value.value.as_ref().unwrap().clone());
            }
        }
    }
    let new_type = if retval.len() == 2 && retval.contains(&Type::Null) {
        let t = retval.iter().find(|t| !t.is_null()).unwrap().clone();
        Type::Dictionary(Box::new(Type::Optional(Box::new(t))))
    } else if retval.len() == 1 {
        Type::Dictionary(Box::new(retval.iter().next().unwrap().clone()))
    } else {
        Type::Dictionary(Box::new(Type::Union(retval.iter().map(|t| t.clone()).collect())))
    };
    ExprInfo {
        r#type: new_type,
        value: if unresolved { None } else { Some(Value::Dictionary(retval_values)) },
        reference_info: None,

    }
}

fn resolve_arith_expr<'a>(arith_expr: &'a ArithExpr, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> ExprInfo {
    match arith_expr {
        ArithExpr::Expression(e) => resolve_expression(e.as_ref(), context, expected, keywords_map),
        ArithExpr::UnaryOperation(unary) => {
            let v = resolve_arith_expr(unary.rhs(), context, expected, keywords_map);
            if !v.r#type().is_undetermined() {
                match unary.op {
                    ArithExprOperator::Neg => {
                        match v.r#type() {
                            Type::Int | Type::Int64 | Type::Float | Type::Float32 | Type::Decimal => ExprInfo {
                                r#type: v.r#type.clone(),
                                value: if let Some(v) = v.value { Some(v.neg().unwrap()) } else { None },
                                reference_info: None,

                            },
                            _ => {
                                context.insert_diagnostics_error(unary.span, "invalid expression");
                                ExprInfo {
                                    r#type: Type::Undetermined,
                                    value: None,
                                    reference_info: None,

                                }
                            }
                        }
                    }
                    ArithExprOperator::Not => ExprInfo {
                        r#type: Type::Bool,
                        value: if let Some(v) = v.value { Some(v.normal_not()) } else { None },
                        reference_info: None,

                    },
                    ArithExprOperator::BitNeg => match v.r#type() {
                        Type::Int | Type::Int64 | Type::Float | Type::Float32 | Type::Decimal => ExprInfo {
                            r#type: v.r#type.clone(),
                            value: if let Some(v) = v.value { Some(v.not().unwrap()) } else { None },
                            reference_info: None,
                        },
                        _ => {
                            context.insert_diagnostics_error(unary.span, "ValueError: invalid expression");
                            ExprInfo {
                                r#type: Type::Undetermined,
                                value: None,
                                reference_info: None,
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            } else {
                v
            }
        }
        ArithExpr::UnaryPostfixOperation(unary) => {
            let v = resolve_arith_expr(unary.lhs(), context, expected, keywords_map);
            ExprInfo {
                r#type: v.r#type.unwrap_optional().clone(),
                value: v.value,
                reference_info: None,
            }
        }
        ArithExpr::BinaryOperation(binary) => {
            let lhs = resolve_arith_expr(binary.lhs(), context, expected, keywords_map);
            let rhs = resolve_arith_expr(binary.rhs(), context, expected, keywords_map);
            let new_type = if !lhs.r#type().is_undetermined() && !rhs.r#type().is_undetermined() {
                match binary.op {
                    ArithExprOperator::Add | ArithExprOperator::Sub | ArithExprOperator::Mul | ArithExprOperator::Div | ArithExprOperator::Mod => {
                        if lhs.r#type().is_int64() && rhs.r#type().is_int_32_or_64() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_int() && rhs.r#type().is_int_32_or_64() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_float() && rhs.r#type().is_any_int_or_float() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_float32() && rhs.r#type().is_any_int_or_float() {
                            lhs.r#type().clone()
                        } else if binary.op == ArithExprOperator::Add && lhs.r#type().is_string() && rhs.r#type().is_string() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_decimal() && rhs.r#type().is_decimal() {
                            lhs.r#type().clone()
                        } else {
                            context.insert_diagnostics_error(binary.span, "invalid expression");
                            Type::Undetermined
                        }
                    }
                    ArithExprOperator::And | ArithExprOperator::Or => if lhs.r#type().test(rhs.r#type()) {
                        lhs.r#type.clone()
                    } else if rhs.r#type().test(lhs.r#type()) {
                        rhs.r#type.clone()
                    } else {
                        Type::Union(vec![lhs.r#type().clone(), rhs.r#type.clone()])
                    }
                    ArithExprOperator::BitAnd | ArithExprOperator::BitXor | ArithExprOperator::BitOr | ArithExprOperator::BitLS | ArithExprOperator::BitRS => {
                        if lhs.r#type().is_int64() && rhs.r#type().is_int_32_or_64() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_int() && rhs.r#type().is_int_32_or_64() {
                            lhs.r#type().clone()
                        } else {
                            context.insert_diagnostics_error(binary.span, "invalid expression");
                            Type::Undetermined
                        }
                    }
                    ArithExprOperator::NullishCoalescing => if lhs.r#type().is_optional() { rhs.r#type().clone() } else { lhs.r#type().clone() },
                    ArithExprOperator::Gt | ArithExprOperator::Gte | ArithExprOperator::Lt | ArithExprOperator::Lte | ArithExprOperator::Eq | ArithExprOperator::Neq => Type::Bool,
                    ArithExprOperator::RangeOpen => if let Some(result) = build_range(lhs.r#type(), rhs.r#type()) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    ArithExprOperator::RangeClose => if let Some(result) = build_range(lhs.r#type(), rhs.r#type()) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    _ => unreachable!()
                }
            } else {
                Type::Undetermined
            };
            let new_value = if new_type.is_undetermined() {
                None
            } else if lhs.value.is_none() || rhs.value.is_none() {
                None
            } else {
                Some(match binary.op {
                    ArithExprOperator::Add => lhs.value.as_ref().unwrap().add(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::Sub => lhs.value.as_ref().unwrap().sub(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::Mul => lhs.value.as_ref().unwrap().mul(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::Div => lhs.value.as_ref().unwrap().div(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::Mod => lhs.value.as_ref().unwrap().rem(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::And => lhs.value.as_ref().unwrap().and(rhs.value.as_ref().unwrap()).clone(),
                    ArithExprOperator::Or => lhs.value.as_ref().unwrap().or(rhs.value.as_ref().unwrap()).clone(),
                    ArithExprOperator::BitAnd => lhs.value.as_ref().unwrap().bitand(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::BitXor => lhs.value.as_ref().unwrap().bitxor(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::BitOr => lhs.value.as_ref().unwrap().bitor(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::BitLS => lhs.value.as_ref().unwrap().shl(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::BitRS => lhs.value.as_ref().unwrap().shr(rhs.value.as_ref().unwrap()).unwrap(),
                    ArithExprOperator::NullishCoalescing => if lhs.value.as_ref().unwrap().is_null() {
                        rhs.value.as_ref().unwrap().clone()
                    } else {
                        rhs.value.as_ref().unwrap().clone()
                    },
                    ArithExprOperator::Gt => Value::Bool(lhs.value.as_ref().unwrap().gt(rhs.value.as_ref().unwrap())),
                    ArithExprOperator::Gte => Value::Bool(lhs.value.as_ref().unwrap() >= rhs.value.as_ref().unwrap()),
                    ArithExprOperator::Lt => Value::Bool(lhs.value.as_ref().unwrap().lt(rhs.value.as_ref().unwrap())),
                    ArithExprOperator::Lte => Value::Bool(lhs.value.as_ref().unwrap() <= rhs.value.as_ref().unwrap()),
                    ArithExprOperator::Eq => Value::Bool(lhs.value.as_ref().unwrap().eq(rhs.value.as_ref().unwrap())),
                    ArithExprOperator::Neq => Value::Bool(!lhs.value.as_ref().unwrap().eq(rhs.value.as_ref().unwrap())),
                    ArithExprOperator::RangeOpen => build_range_value(lhs.value.as_ref().unwrap(), rhs.value.as_ref().unwrap(), false),
                    ArithExprOperator::RangeClose => build_range_value(lhs.value.as_ref().unwrap(), rhs.value.as_ref().unwrap(), true),
                    _ => unreachable!()
                })
            };
            ExprInfo {
                r#type: new_type,
                value: new_value,
                reference_info: None,
            }
        }
    }
}

fn build_range(lhs: &Type, rhs: &Type) -> Option<Type> {
    let valid = if lhs.is_int() && rhs.is_int() {
        true
    } else if lhs.is_int64() && rhs.is_int64() {
        true
    } else if lhs.is_float32() && rhs.is_float32() {
        true
    } else if lhs.is_float() && rhs.is_float() {
        true
    } else if lhs.is_decimal() && rhs.is_decimal() {
        true
    } else if lhs.is_date() && rhs.is_date() {
        true
    } else if lhs.is_datetime() && rhs.is_datetime() {
        true
    } else {
        false
    };
    if valid {
        Some(Type::Range(Box::new(lhs.clone())))
    } else {
        None
    }
}

fn build_range_value(lhs: &Value, rhs: &Value, closed: bool) -> Value {
    Value::Range(Range {
        closed,
        start: Box::new(lhs.clone()),
        end: Box::new(rhs.clone()),
    })
}

pub(super) fn resolve_expression_for_named_expression_key<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> ExprInfo {
    expression.resolve_and_return(match &expression.kind {
        ExpressionKind::StringLiteral(s) => resolve_string_literal(s, context, expected),
        ExpressionKind::Identifier(i) => ExprInfo::new(Type::String, Some(Value::String(i.name.clone())), None),
        ExpressionKind::BracketExpression(e) => resolve_bracket_expression(e, context, expected, keywords_map),
        _ => unreachable!(),
    })
}

fn resolve_bracket_expression<'a>(bracket_expression: &'a BracketExpression, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> ExprInfo {
    resolve_expression(bracket_expression.expression(), context, expected, keywords_map)
}