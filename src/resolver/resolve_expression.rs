use std::collections::BTreeMap;
use std::default::Default;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};
use indexmap::IndexMap;
use maplit::{btreemap, hashset};
use teo_teon::types::enum_variant::EnumVariant;
use teo_teon::types::range::Range;
use teo_teon::Value;
use teo_teon::types::option_variant::OptionVariant;
use crate::ast::arith::{ArithExpr, Op};
use crate::ast::callable_variant::CallableVariant;
use crate::ast::expression::{Expression, ExpressionKind, TypeAndValue};
use crate::ast::group::Group;
use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, EnumVariantLiteral, NullLiteral, NumericLiteral, RegexLiteral, StringLiteral, TupleLiteral};
use crate::diagnostics::diagnostics::DiagnosticsError;
use crate::r#type::keyword::Keyword;
use crate::r#type::r#type::Type;
use crate::r#type::synthesized_enum::SynthesizedEnum;
use crate::resolver::resolve_argument_list::resolve_argument_list;
use crate::resolver::resolve_identifier::resolve_identifier_with_diagnostic_message;
use crate::resolver::resolve_pipeline::resolve_pipeline;
use crate::resolver::resolve_unit::resolve_unit;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_expression<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>) -> TypeAndValue {
    let t = resolve_expression_kind(&expression.kind, context, expected, keywords_map);
    expression.resolve(t.clone());
    t
}

fn resolve_expression_kind<'a>(expression: &'a ExpressionKind, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> TypeAndValue {
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
    }
}

fn resolve_group<'a>(group: &'a Group, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> TypeAndValue {
    resolve_expression(&group.expression, context, expected, keywords_map)
}

fn resolve_numeric_literal<'a>(n: &NumericLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> TypeAndValue {
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
            TypeAndValue {
                r#type: Type::Int64,
                value: Some(n.value.clone()),
            }
        } else if n.value.is_int() {
            TypeAndValue {
                r#type: Type::Int,
                value: Some(n.value.clone()),
            }
        } else if n.value.is_float() {
            TypeAndValue {
                r#type: Type::Float,
                value: Some(n.value.clone()),
            }
        } else {
            unreachable!()
        },
        Type::Int => if n.value.is_any_int() {
            TypeAndValue {
                r#type: Type::Int,
                value: Some(Value::Int(n.value.to_int().unwrap())),
            }
        } else {
            context.insert_diagnostics_error(n.span, "value is not int");
            TypeAndValue::undetermined()
        },
        Type::Int64 => if n.value.is_any_int() {
            TypeAndValue {
                r#type: Type::Int64,
                value: Some(Value::Int64(n.value.to_int64().unwrap())),
            }
        } else {
            context.insert_diagnostics_error(n.span, "value is not int64");
            TypeAndValue::undetermined()
        },
        Type::Float32 => if n.value.is_any_float() {
            TypeAndValue {
                r#type: Type::Float32,
                value: Some(Value::Float32(n.value.to_float32().unwrap())),
            }
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            TypeAndValue::undetermined()
        },
        Type::Float => if n.value.is_any_float() {
            TypeAndValue {
                r#type: Type::Float,
                value: Some(Value::Float(n.value.to_float().unwrap())),
            }
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            TypeAndValue::undetermined()
        },
        _ => {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            TypeAndValue::undetermined()
        }
    }
}

fn resolve_string_literal<'a>(s: &StringLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> TypeAndValue {
    TypeAndValue {
        r#type: Type::String,
        value: Some(Value::String(s.value.clone())),
    }
}

fn resolve_regex_literal<'a>(r: &RegexLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> TypeAndValue {
    TypeAndValue {
        r#type: Type::Regex,
        value: Some(Value::Regex(r.value.clone())),
    }
}

fn resolve_bool_literal<'a>(r: &BoolLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> TypeAndValue {
    TypeAndValue {
        r#type: Type::Bool,
        value: Some(Value::Bool(r.value)),
    }
}

fn resolve_null_literal<'a>(n: &NullLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> TypeAndValue {
    TypeAndValue {
        r#type: Type::Null,
        value: Some(Value::Null),
    }
}

pub(super) fn resolve_enum_variant_literal<'a>(e: &'a EnumVariantLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> TypeAndValue {
    if let Some(enum_reference) = expected.as_enum_variant() {
        let r#enum = context.schema.find_top_by_path(enum_reference.path()).unwrap().as_enum().unwrap();
        let Some(member) = r#enum.members.iter().find(|m| m.identifier.name() == e.identifier.name()) else {
            context.insert_diagnostics_error(e.span, format!("expect {}, found .{}", enum_reference.string_path().join("."), e.identifier.name()));
            return TypeAndValue {
                r#type: Type::EnumVariant(enum_reference.clone()),
                value: None,
            }
        };
        if let Some(argument_list_declaration) = &member.argument_list_declaration {
            if let Some(argument_list) = &e.argument_list {
                resolve_argument_list(
                    e.identifier.span,
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
                return TypeAndValue {
                    r#type: Type::EnumVariant(enum_reference.clone()),
                    value: None,
                }
            }
        }
        if r#enum.option {
            TypeAndValue {
                r#type: Type::EnumVariant(enum_reference.clone()),
                value: Some(Value::OptionVariant(OptionVariant {
                    value: member.resolved().value.as_int().unwrap(),
                    display: format!(".{}", member.identifier.name()),
                }))
            }
        } else {
            TypeAndValue {
                r#type: Type::EnumVariant(enum_reference.clone()),
                value: Some(Value::EnumVariant(EnumVariant {
                    value: member.resolved().value.as_str().unwrap().to_string(),
                    args: None,
                }))
            }
        }
    } else if let Some(synthesized_enum) = expected.as_synthesized_enum() {
        resolve_enum_variant_literal_from_synthesized_enum(e, synthesized_enum, context)
    } else if let Some(reference) = expected.as_synthesized_enum_variant_reference() {
        if let Some(synthesized_enum) = reference.fetch_synthesized_definition(context.schema) {
            resolve_enum_variant_literal_from_synthesized_enum(e, synthesized_enum, context)
        } else {
            context.insert_diagnostics_error(e.span, format!("expect {}, found .{}", reference, e.identifier.name()));
            TypeAndValue {
                r#type: Type::SynthesizedEnumReference(reference.clone()),
                value: None
            }
        }
    } else {
        context.insert_diagnostics_error(e.span, format!("expected {}, found .{}", expected, e.identifier.name()));
        TypeAndValue {
            r#type: expected.clone(),
            value: None
        }
    }
}

fn resolve_enum_variant_literal_from_synthesized_enum<'a>(e: &EnumVariantLiteral, synthesized_enum: &SynthesizedEnum, context: &'a ResolverContext<'a>) -> TypeAndValue {
    if synthesized_enum.keys.contains(&e.identifier.name) {
        TypeAndValue {
            r#type: Type::SynthesizedEnum(synthesized_enum.clone()),
            value: Some(Value::EnumVariant(EnumVariant {
                value: e.identifier.name.to_string(),
                args: None,
            }))
        }
    } else {
        context.insert_diagnostics_error(e.span, format!("expect {}, found .{}", synthesized_enum, e.identifier.name()));
        TypeAndValue {
            r#type: Type::SynthesizedEnum(synthesized_enum.clone()),
            value: None
        }
    }
}

fn resolve_tuple_literal<'a>(t: &'a TupleLiteral, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> TypeAndValue {
    let types = expected.as_tuple();
    let mut retval_values = vec![];
    let mut retval_type = vec![];
    let mut unresolved = false;
    let undetermined = Type::Undetermined;
    for (i, e) in t.expressions.iter().enumerate() {
        let resolved = resolve_expression(e, context, types.map(|t| t.get(i)).flatten().unwrap_or(&undetermined), keywords_map);
        if resolved.value.is_none() {
            unresolved = true;
        } else {
            retval_values.push(resolved.value.unwrap())
        }
        retval_type.push(resolved.r#type);
    }
    TypeAndValue {
        r#type: Type::Tuple(retval_type),
        value: if unresolved { None } else { Some(Value::Tuple(retval_values)) }
    }
}

fn resolve_array_literal<'a>(a: &'a ArrayLiteral, context: &'a ResolverContext<'a>, mut expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> TypeAndValue {
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
    for e in a.expressions.iter() {
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
    TypeAndValue {
        r#type: new_type,
        value: if unresolved { None } else { Some(Value::Array(retval_values)) }
    }
}

fn resolve_dictionary_literal<'a>(a: &'a DictionaryLiteral, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> TypeAndValue {
    let undetermined = Type::Undetermined;
    let r#type = if let Some(v) = expected.as_dictionary() {
        v
    } else {
        &undetermined
    };
    let mut retval = hashset![];
    let mut retval_values = IndexMap::new();
    let mut unresolved = false;
    for (k, v) in a.expressions.iter() {
        let k_value = resolve_expression(k, context, &Type::String, keywords_map);
        if !k_value.r#type.is_string() {
            context.insert_diagnostics_error(k.span(), "ValueError: dictionary key is not String");
        }
        let v_value = resolve_expression(v, context, r#type, keywords_map);
        retval.insert(v_value.r#type.clone());
        if k_value.value.is_none() || v_value.value.is_none() {
            unresolved = true;
        } else {
            retval_values.insert(k_value.value.as_ref().unwrap().as_str().unwrap().to_owned(), v_value.value.as_ref().unwrap().clone());
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
    TypeAndValue {
        r#type: new_type,
        value: if unresolved { None } else { Some(Value::Dictionary(retval_values)) }
    }
}

fn resolve_arith_expr<'a>(arith_expr: &'a ArithExpr, context: &'a ResolverContext<'a>, expected: &Type, keywords_map: &BTreeMap<Keyword, Type>,) -> TypeAndValue {
    match arith_expr {
        ArithExpr::Expression(e) => resolve_expression(e.as_ref(), context, expected, keywords_map),
        ArithExpr::UnaryOp(unary) => {
            let v = resolve_arith_expr(unary.rhs.as_ref(), context, expected, keywords_map);
            if !v.r#type().is_undetermined() {
                match unary.op {
                    Op::Neg => {
                        match v.r#type() {
                            Type::Int | Type::Int64 | Type::Float | Type::Float32 | Type::Decimal => TypeAndValue {
                                r#type: v.r#type.clone(),
                                value: if let Some(v) = v.value { Some(v.neg().unwrap()) } else { None }
                            },
                            _ => {
                                context.insert_diagnostics_error(unary.span, "invalid expression");
                                TypeAndValue {
                                    r#type: Type::Undetermined,
                                    value: None,
                                }
                            }
                        }
                    }
                    Op::Not => TypeAndValue {
                        r#type: Type::Bool,
                        value: if let Some(v) = v.value { Some(v.normal_not()) } else { None }
                    },
                    Op::BitNeg => match v.r#type() {
                        Type::Int | Type::Int64 | Type::Float | Type::Float32 | Type::Decimal => TypeAndValue {
                            r#type: v.r#type.clone(),
                            value: if let Some(v) = v.value { Some(v.not().unwrap()) } else { None }
                        },
                        _ => {
                            context.insert_diagnostics_error(unary.span, "ValueError: invalid expression");
                            TypeAndValue {
                                r#type: Type::Undetermined,
                                value: None,
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            } else {
                v
            }
        }
        ArithExpr::UnaryPostfixOp(unary) => {
            let v = resolve_arith_expr(unary.lhs.as_ref(), context, expected, keywords_map);
            TypeAndValue {
                r#type: v.r#type.unwrap_optional().clone(),
                value: v.value
            }
        }
        ArithExpr::BinaryOp(binary) => {
            let lhs = resolve_arith_expr(binary.lhs.as_ref(), context, expected, keywords_map);
            let rhs = resolve_arith_expr(binary.rhs.as_ref(), context, expected, keywords_map);
            let new_type = if !lhs.r#type().is_undetermined() && !rhs.r#type().is_undetermined() {
                match binary.op {
                    Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Mod => {
                        if lhs.r#type().is_int64() && rhs.r#type().is_int_32_or_64() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_int() && rhs.r#type().is_int_32_or_64() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_float() && rhs.r#type().is_any_int_or_float() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_float32() && rhs.r#type().is_any_int_or_float() {
                            lhs.r#type().clone()
                        } else if binary.op == Op::Add && lhs.r#type().is_string() && rhs.r#type().is_string() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_decimal() && rhs.r#type().is_decimal() {
                            lhs.r#type().clone()
                        } else {
                            context.insert_diagnostics_error(binary.span, "invalid expression");
                            Type::Undetermined
                        }
                    }
                    Op::And | Op::Or => if lhs.r#type().test(rhs.r#type()) {
                        lhs.r#type.clone()
                    } else if rhs.r#type().test(lhs.r#type()) {
                        rhs.r#type.clone()
                    } else {
                        Type::Union(vec![lhs.r#type().clone(), rhs.r#type.clone()])
                    }
                    Op::BitAnd | Op::BitXor | Op::BitOr | Op::BitLS | Op::BitRS => {
                        if lhs.r#type().is_int64() && rhs.r#type().is_int_32_or_64() {
                            lhs.r#type().clone()
                        } else if lhs.r#type().is_int() && rhs.r#type().is_int_32_or_64() {
                            lhs.r#type().clone()
                        } else {
                            context.insert_diagnostics_error(binary.span, "invalid expression");
                            Type::Undetermined
                        }
                    }
                    Op::NullishCoalescing => if lhs.r#type().is_optional() { rhs.r#type().clone() } else { lhs.r#type().clone() },
                    Op::Gt | Op::Gte | Op::Lt | Op::Lte | Op::Eq | Op::Neq => Type::Bool,
                    Op::RangeOpen => if let Some(result) = build_range(lhs.r#type(), rhs.r#type()) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::RangeClose => if let Some(result) = build_range(lhs.r#type(), rhs.r#type()) {
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
                    Op::Add => lhs.value.as_ref().unwrap().add(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::Sub => lhs.value.as_ref().unwrap().sub(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::Mul => lhs.value.as_ref().unwrap().mul(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::Div => lhs.value.as_ref().unwrap().div(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::Mod => lhs.value.as_ref().unwrap().rem(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::And => lhs.value.as_ref().unwrap().and(rhs.value.as_ref().unwrap()).clone(),
                    Op::Or => lhs.value.as_ref().unwrap().or(rhs.value.as_ref().unwrap()).clone(),
                    Op::BitAnd => lhs.value.as_ref().unwrap().bitand(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::BitXor => lhs.value.as_ref().unwrap().bitxor(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::BitOr => lhs.value.as_ref().unwrap().bitor(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::BitLS => lhs.value.as_ref().unwrap().shl(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::BitRS => lhs.value.as_ref().unwrap().shr(rhs.value.as_ref().unwrap()).unwrap(),
                    Op::NullishCoalescing => if lhs.value.as_ref().unwrap().is_null() {
                        rhs.value.as_ref().unwrap().clone()
                    } else {
                        rhs.value.as_ref().unwrap().clone()
                    },
                    Op::Gt => Value::Bool(lhs.value.as_ref().unwrap().gt(rhs.value.as_ref().unwrap())),
                    Op::Gte => Value::Bool(lhs.value.as_ref().unwrap() >= rhs.value.as_ref().unwrap()),
                    Op::Lt => Value::Bool(lhs.value.as_ref().unwrap().lt(rhs.value.as_ref().unwrap())),
                    Op::Lte => Value::Bool(lhs.value.as_ref().unwrap() <= rhs.value.as_ref().unwrap()),
                    Op::Eq => Value::Bool(lhs.value.as_ref().unwrap().eq(rhs.value.as_ref().unwrap())),
                    Op::Neq => Value::Bool(!lhs.value.as_ref().unwrap().eq(rhs.value.as_ref().unwrap())),
                    Op::RangeOpen => build_range_value(lhs.value.as_ref().unwrap(), rhs.value.as_ref().unwrap(), false),
                    Op::RangeClose => build_range_value(lhs.value.as_ref().unwrap(), rhs.value.as_ref().unwrap(), true),
                    _ => unreachable!()
                })
            };
            TypeAndValue {
                r#type: new_type,
                value: new_value,
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
