use std::default::Default;
use maplit::{hashset};
use crate::ast::arith::{ArithExpr, Op};
use crate::ast::expr::{Expression, ExpressionKind};
use crate::ast::group::Group;
use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, EnumVariantLiteral, NullLiteral, NumericLiteral, RegExpLiteral, StringLiteral, TupleLiteral};
use crate::diagnostics::diagnostics::DiagnosticsError;
use crate::r#type::r#type::Type;
use crate::resolver::resolve_identifier::resolve_identifier_into_type;
use crate::resolver::resolve_pipeline::resolve_pipeline;
use crate::resolver::resolve_unit::resolve_unit;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_expression<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type) {
    expression.resolve(resolve_expression_kind(&expression.kind, context, expected))
}

pub(super) fn resolve_expression_kind<'a>(expression: &'a ExpressionKind, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    match &expression {
        ExpressionKind::Group(e) => resolve_group(e, context, expected),
        ExpressionKind::ArithExpr(e) => resolve_arith_expr(e, context, expected),
        ExpressionKind::NumericLiteral(n) => resolve_numeric_literal(n, context, expected),
        ExpressionKind::StringLiteral(e) => resolve_string_literal(e, context, expected),
        ExpressionKind::RegExpLiteral(e) => resolve_regexp_literal(e, context, expected),
        ExpressionKind::BoolLiteral(b) => resolve_bool_literal(b, context, expected),
        ExpressionKind::NullLiteral(n) => resolve_null_literal(n, context, expected),
        ExpressionKind::EnumVariantLiteral(e) => resolve_enum_variant_literal(e, context, expected),
        ExpressionKind::TupleLiteral(t) => resolve_tuple_literal(t, context, expected),
        ExpressionKind::ArrayLiteral(a) => resolve_array_literal(a, context, expected),
        ExpressionKind::DictionaryLiteral(d) => resolve_dictionary_literal(d, context, expected),
        ExpressionKind::Identifier(i) => resolve_identifier_into_type(i, context),
        ExpressionKind::ArgumentList(_) => unreachable!(),
        ExpressionKind::Subscript(_) => unreachable!(),
        ExpressionKind::Unit(u) => resolve_unit(u, context, expected),
        ExpressionKind::Pipeline(p) => resolve_pipeline(p, context),
        ExpressionKind::Call(_) => unreachable!(),
    }
}

fn resolve_group<'a>(group: &'a Group, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    resolve_expression_kind(&group.expression, context, expected)
}

fn resolve_numeric_literal<'a>(n: &NumericLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    match expected {
        Type::Undetermined => if n.value.is_int64() {
            Type::Int64
        } else if n.value.is_int() {
            Type::Int
        } else if n.value.is_float() {
            Type::Float
        } else {
            unreachable!()
        },
        Type::Int => if n.value.is_any_int() {
            Type::Int
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Type::Undetermined
        },
        Type::Int64 => if n.value.is_any_int() {
            Type::Int64
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Type::Undetermined
        },
        Type::Float32 => if n.value.is_any_float() {
            Type::Float32
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Type::Undetermined
        },
        Type::Float => if n.value.is_any_float() {
            Type::Float
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Type::Undetermined
        },
        _ => {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Type::Undetermined
        }
    }
}

fn resolve_string_literal<'a>(s: &StringLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    Type::String
}

fn resolve_regexp_literal<'a>(r: &RegExpLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    Type::Regex
}

fn resolve_bool_literal<'a>(r: &BoolLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    Type::Bool
}

fn resolve_null_literal<'a>(r: &NullLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    Type::Null
}

pub(super) fn resolve_enum_variant_literal<'a>(e: &EnumVariantLiteral, context: &'a ResolverContext<'a>, mut expected: &Type) -> Type {
    if expected.is_optional() {
        expected = expected.unwrap_optional();
    }
    if let Some(types) = expected.as_union() {
        for expected in types {
            if let Ok(t) = try_resolve_enum_variant_literal(e, context, expected) {
                return t
            }
        }
        context.insert_diagnostics_error(e.span, "unexpected enum variant literal");
        Type::Undetermined
    } else {
        match try_resolve_enum_variant_literal(e, context, expected) {
            Ok(t) => t,
            Err(err) => {
                context.insert_error(err);
                Type::Undetermined
            }
        }
    }
}

fn try_resolve_enum_variant_literal<'a>(e: &EnumVariantLiteral, context: &'a ResolverContext<'a>, mut expected: &Type) -> Result<Type, DiagnosticsError> {
    if expected.is_optional() {
        expected = expected.unwrap_optional();
    }
    if let Some(enum_path) = expected.as_enum_variant() {
        let r#enum = context.schema.find_top_by_path(enum_path).unwrap().as_enum().unwrap();
        if let Some(_) = r#enum.members.iter().find(|m| m.identifier.name() == e.identifier.name()) {
            Ok(Type::EnumVariant(enum_path.clone()))
        } else {
            Err(context.generate_diagnostics_error(e.span, "ValueError: undefined enum member"))
        }
    } else if let Some(t) = expected.as_model_scalar_fields() {
        if let Some(model_object) = t.as_model_object() {
            let model = context.schema.find_top_by_path(model_object).unwrap().as_model().unwrap();
            if model.resolved().scalar_fields.contains(&e.identifier.name) {
                Ok(Type::ModelScalarFields(Box::new(Type::ModelObject(model_object.clone()))))
            } else {
                Err(context.generate_diagnostics_error(e.span, "undefined model scalar fields"))
            }
        } else {
            Err(context.generate_diagnostics_error(e.span, "ValueError: unexpected enum variant literal"))
        }
    } else if let Some(t) = expected.as_model_scalar_fields_without_virtuals() {
        if let Some(model_object) = t.as_model_object() {
            let model = context.schema.find_top_by_path(model_object).unwrap().as_model().unwrap();
            if model.resolved().scalar_fields_without_virtuals.contains(&e.identifier.name) {
                Ok(Type::ModelScalarFieldsWithoutVirtuals(Box::new(Type::ModelObject(model_object.clone()))))
            } else {
                Err(context.generate_diagnostics_error(e.span, "undefined model scalar fields without virtuals"))
            }
        } else {
            Err(context.generate_diagnostics_error(e.span, "ValueError: unexpected enum variant literal"))
        }
    } else if let Some(t) = expected.as_model_scalar_fields_and_cached_properties_without_virtuals() {
        if let Some(model_object) = t.as_model_object() {
            let model = context.schema.find_top_by_path(model_object).unwrap().as_model().unwrap();
            if model.resolved().scalar_fields_and_cached_properties_without_virtuals.contains(&e.identifier.name) {
                Ok(Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(Box::new(Type::ModelObject(model_object.clone()))))
            } else {
                Err(context.generate_diagnostics_error(e.span, "undefined model scalar fields and cached properties without virtuals"))
            }
        } else {
            Err(context.generate_diagnostics_error(e.span, "ValueError: unexpected enum variant literal"))
        }
    } else {
        Err(context.generate_diagnostics_error(e.span, "ValueError: unexpected enum variant literal"))
    }
}

fn resolve_tuple_literal<'a>(t: &'a TupleLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    let types = expected.as_tuple();
    let mut retval = vec![];
    let undetermined = Type::Undetermined;
    for (i, e) in t.expressions.iter().enumerate() {
        retval.push(resolve_expression_kind(e, context, types.map(|t| t.get(i)).flatten().unwrap_or(&undetermined)));
    }
    Type::Tuple(retval)
}

fn resolve_array_literal<'a>(a: &'a ArrayLiteral, context: &'a ResolverContext<'a>, mut expected: &Type) -> Type {
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
    for e in a.expressions.iter() {
        retval.insert(resolve_expression_kind(e, context, r#type));
    }
    if retval.len() == 2 && retval.contains(&Type::Null) {
        let t = retval.iter().find(|t| !t.is_null()).unwrap().clone();
        Type::Array(Box::new(Type::Optional(Box::new(t))))
    } else if retval.len() == 1 {
        Type::Array(Box::new(retval.iter().next().unwrap().clone()))
    } else {
        Type::Array(Box::new(Type::Union(retval.iter().map(|t| t.clone()).collect())))
    }
}

fn resolve_dictionary_literal<'a>(a: &'a DictionaryLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    let undetermined = Type::Undetermined;
    let r#type = if let Some(v) = expected.as_dictionary() {
        v
    } else {
        &undetermined
    };
    let mut retval = hashset![];
    for (k, v) in a.expressions.iter() {
        let k_value = resolve_expression_kind(k, context, &Type::String);
        if !k_value.is_string() {
            context.insert_diagnostics_error(k.span(), "ValueError: dictionary key is not String");
        }
        let v_value = resolve_expression_kind(v, context, r#type);
        retval.insert(v_value);
    }
    if retval.len() == 2 && retval.contains(&Type::Null) {
        let t = retval.iter().find(|t| !t.is_null()).unwrap().clone();
        Type::Dictionary(Box::new(Type::Optional(Box::new(t))))
    } else if retval.len() == 1 {
        Type::Dictionary(Box::new(retval.iter().next().unwrap().clone()))
    } else {
        Type::Dictionary(Box::new(Type::Union(retval.iter().map(|t| t.clone()).collect())))
    }
}

fn resolve_arith_expr<'a>(arith_expr: &'a ArithExpr, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    match arith_expr {
        ArithExpr::Expression(e) => resolve_expression_kind(e.as_ref(), context, expected),
        ArithExpr::UnaryOp(unary) => {
            let v = resolve_arith_expr(unary.rhs.as_ref(), context, expected);
            if !v.is_undetermined() {
                match unary.op {
                    Op::Neg => {
                        match v {
                            Type::Int | Type::Int64 | Type::Float | Type::Float32 | Type::Decimal => v,
                            _ => {
                                context.insert_diagnostics_error(unary.span, "ValueError: invalid expression");
                                Type::Undetermined
                            }
                        }
                    }
                    Op::Not => Type::Bool,
                    Op::BitNeg => match v {
                        Type::Int | Type::Int64 | Type::Float | Type::Float32 | Type::Decimal => v,
                        _ => {
                            context.insert_diagnostics_error(unary.span, "ValueError: invalid expression");
                            Type::Undetermined
                        }
                    }
                    _ => unreachable!(),
                }
            } else {
                v
            }
        }
        ArithExpr::BinaryOp(binary) => {
            let lhs = resolve_arith_expr(binary.lhs.as_ref(), context, expected);
            let rhs = resolve_arith_expr(binary.rhs.as_ref(), context, expected);
            if !lhs.is_undetermined() && !rhs.is_undetermined() {
                match binary.op {
                    Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Mod => {
                        if lhs.is_int64() && rhs.is_int_32_or_64() {
                            lhs
                        } else if lhs.is_int() && rhs.is_int_32_or_64() {
                            lhs
                        } else if lhs.is_float() && rhs.is_any_int_or_float() {
                            lhs
                        } else if lhs.is_float32() && rhs.is_any_int_or_float() {
                            lhs
                        } else if binary.op == Op::Add && lhs.is_string() && rhs.is_string() {
                            lhs
                        } else if lhs.is_decimal() && rhs.is_decimal() {
                            lhs
                        } else {
                            context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                            Type::Undetermined
                        }
                    }
                    Op::And | Op::Or => if lhs.test(&rhs) {
                        lhs
                    } else if rhs.test(&lhs) {
                        rhs
                    } else {
                        Type::Union(vec![lhs, rhs])
                    }
                    Op::BitAnd | Op::BitXor | Op::BitOr | Op::BitLS | Op::BitRS => {
                        if lhs.is_int64() && rhs.is_int_32_or_64() {
                            lhs
                        } else if lhs.is_int() && rhs.is_int_32_or_64() {
                            lhs
                        } else {
                            context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                            Type::Undetermined
                        }
                    }
                    Op::NullishCoalescing => if lhs.is_optional() { rhs } else { lhs },
                    Op::Gt | Op::Gte | Op::Lt | Op::Lte | Op::Eq | Op::Neq => Type::Bool,
                    Op::RangeOpen => if let Some(result) = build_range(&lhs, &rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::RangeClose => if let Some(result) = build_range(&lhs, &rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    _ => unreachable!()
                }
            } else {
                Type::Undetermined
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
