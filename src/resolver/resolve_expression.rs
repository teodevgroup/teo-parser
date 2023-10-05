use std::default::Default;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};
use maplit::hashmap;
use teo_teon::types::enum_variant::EnumVariant;
use teo_teon::types::range::Range;
use teo_teon::value::Value;
use crate::ast::accessible::Accessible;
use crate::ast::arith::{ArithExpr, Op};
use crate::ast::expr::{Expression, ExpressionKind};
use crate::ast::group::Group;
use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, EnumVariantLiteral, NullLiteral, NumericLiteral, RegExpLiteral, StringLiteral, TupleLiteral};
use crate::ast::r#type::Type;
use crate::ast::reference::{Reference, ReferenceType};
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::ast::unit::Unit;
use crate::resolver::resolve_constant::resolve_constant;
use crate::resolver::resolve_identifier::{resolve_identifier, top_filter_for_reference_type};
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_expression<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type) {
    expression.resolve(resolve_expression_kind(&expression.kind, context, expected))
}

pub(super) fn resolve_expression_and_unwrap_value<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type) {
    expression.resolve(Accessible::Value(resolve_expression_kind_and_unwrap_value(&expression.kind, context, expected)))
}

pub(super) fn resolve_expression_kind<'a>(expression: &'a ExpressionKind, context: &'a ResolverContext<'a>, expected: &Type) -> Accessible {
    match &expression {
        ExpressionKind::Group(e) => resolve_group(e, context, expected),
        ExpressionKind::ArithExpr(e) => Accessible::Value(resolve_arith_expr(e, context, expected)),
        ExpressionKind::NumericLiteral(n) => Accessible::Value(resolve_numeric_literal(n, context, expected)),
        ExpressionKind::StringLiteral(e) => Accessible::Value(resolve_string_literal(e, context, expected)),
        ExpressionKind::RegExpLiteral(e) => Accessible::Value(resolve_regexp_literal(e, context, expected)),
        ExpressionKind::BoolLiteral(b) => Accessible::Value(resolve_bool_literal(b, context, expected)),
        ExpressionKind::NullLiteral(n) => Accessible::Value(resolve_null_literal(n, context, expected)),
        ExpressionKind::EnumVariantLiteral(e) => Accessible::Value(resolve_enum_variant_literal(e, context, expected)),
        ExpressionKind::TupleLiteral(t) => Accessible::Value(resolve_tuple_literal(t, context, expected)),
        ExpressionKind::ArrayLiteral(a) => Accessible::Value(resolve_array_literal(a, context, expected)),
        ExpressionKind::DictionaryLiteral(d) => Accessible::Value(resolve_dictionary_literal(d, context, expected)),
        ExpressionKind::Identifier(i) => if let Some(reference) = resolve_identifier(i, context, ReferenceType::Default) {
            Accessible::Reference(reference.clone())
        } else {
            context.insert_diagnostics_error(i.span, "ReferenceError: undefined identifier");
            Accessible::Value(Value::Undetermined)
        }
        ExpressionKind::ArgumentList(_) => unreachable!(),
        ExpressionKind::Subscript(_) => unreachable!(),
        ExpressionKind::Unit(u) => resolve_unit(u, context, expected),
        ExpressionKind::Pipeline(p) => resolve_pipeline(p, context, expected),
    }
}

pub(super) fn resolve_expression_kind_and_unwrap_value<'a>(expression: &'a ExpressionKind, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    let result = resolve_expression_kind(expression, context, expected);
    if result.is_reference() {
        // do things here to resolve
        Value::Undetermined
    } else {
        result.into_value().unwrap()
    }
}

fn resolve_group<'a>(group: &Group, context: &'a ResolverContext<'a>, expected: &Type) -> Accessible {
    resolve_expression_kind(&group.expression, context, expected)
}

fn resolve_numeric_literal<'a>(n: &NumericLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    match expected {
        Type::Undetermined => n.value.clone(),
        Type::Int => if n.value.is_any_int() {
            Value::Int(n.value.to_int().unwrap())
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        },
        Type::Int64 => if n.value.is_any_int() {
            Value::Int64(n.value.to_int64().unwrap())
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        },
        Type::Float32 => if n.value.is_any_float() {
            Value::Float32(n.value.to_float32().unwrap())
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        },
        Type::Float => if n.value.is_any_float() {
            Value::Float(n.value.to_float().unwrap())
        } else {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        },
        _ => {
            context.insert_diagnostics_error(n.span, "ValueError: value is of wrong type");
            Value::Undetermined
        }
    }
}

fn resolve_string_literal<'a>(s: &StringLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    Value::String(s.value.clone())
}

fn resolve_regexp_literal<'a>(r: &RegExpLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    Value::RegExp(r.value.clone())
}

fn resolve_bool_literal<'a>(r: &BoolLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    Value::Bool(r.value)
}

fn resolve_null_literal<'a>(r: &NullLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    Value::Null
}

fn resolve_enum_variant_literal<'a>(e: &EnumVariantLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    if let Some(enum_path) = expected.enum_path() {
        let r#enum = context.schema.find_top_by_path(enum_path).unwrap().as_enum().unwrap();
        if let Some(member) = r#enum.members.iter().find(|m| m.identifier.name() == e.identifier.name()) {
            Value::EnumVariant(EnumVariant {
                value: Box::new(member.resolved().value.clone()),
                display: format!(".{}", member.identifier.name()),
                path: enum_path.clone(),
                args: None,
            })
        } else {
            context.insert_diagnostics_error(e.span, "ValueError: undefined enum member");
            Value::Undetermined
        }
    } else {
        context.insert_diagnostics_error(e.span, "ValueError: unexpected enum variant literal");
        Value::Undetermined
    }
}

fn resolve_tuple_literal<'a>(t: &TupleLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    let types = expected.as_tuple();
    let mut retval = vec![];
    let undetermined = Type::Undetermined;
    for (i, e) in t.expressions.iter().enumerate() {
        retval.push(resolve_expression_kind_and_unwrap_value(e, context, types.map(|t| t.get(i)).flatten().unwrap_or(&undetermined)));
    }
    Value::Tuple(retval)
}

fn resolve_array_literal<'a>(a: &ArrayLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    let r#type = expected.as_array();
    let mut retval = vec![];
    let undetermined = Type::Undetermined;
    for (i, e) in a.expressions.iter().enumerate() {
        retval.push(resolve_expression_kind_and_unwrap_value(e, context, r#type.unwrap_or(&undetermined)));
    }
    Value::Array(retval)
}

fn resolve_dictionary_literal<'a>(a: &DictionaryLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    let undetermined = Type::Undetermined;
    let r#type = if let Some(v) = expected.as_dictionary() {
        v
    } else {
        &undetermined
    };
    let mut retval = hashmap!{};
    for (k, v) in a.expressions.iter() {
        let k_value = resolve_expression_kind_and_unwrap_value(k, context, &Type::String);
        if !k_value.is_string() {
            context.insert_diagnostics_error(k.span(), "ValueError: dictionary key is not String");
        }
        let k_str = k_value.as_str().unwrap().to_owned();
        let v_value = resolve_expression_kind_and_unwrap_value(v, context, r#type);
        retval.insert(k_str, v_value);
    }
    Value::Dictionary(retval)
}

fn resolve_arith_expr<'a>(arith_expr: &ArithExpr, context: &'a ResolverContext<'a>, expected: &Type) -> Value {
    match arith_expr {
        ArithExpr::Expression(e) => resolve_expression_kind_and_unwrap_value(e.as_ref(), context, expected),
        ArithExpr::UnaryOp(unary) => {
            let v = resolve_arith_expr(unary.rhs.as_ref(), context, expected);
            if !v.is_undetermined() {
                match unary.op {
                    Op::Neg => if let Ok(result) = v.neg() {
                        result
                    } else {
                        context.insert_diagnostics_error(unary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::Not => v.normal_not(),
                    Op::BitNeg => if let Ok(result) = v.not() {
                        result
                    } else {
                        context.insert_diagnostics_error(unary.span, "ValueError: invalid expression");
                        Value::Undetermined
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
                    Op::Add => if let Ok(result) = lhs.add(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::Sub => if let Ok(result) = lhs.sub(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::Mul => if let Ok(result) = lhs.mul(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::Div => if let Ok(result) = lhs.div(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::Mod => if let Ok(result) = lhs.rem(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::And => if lhs.normal_not().as_bool().unwrap() { lhs } else { rhs }
                    Op::Or => if lhs.normal_not().as_bool().unwrap() { rhs } else { lhs }
                    Op::BitAnd => if let Ok(result) = lhs.bitand(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::BitXor => if let Ok(result) = lhs.bitxor(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::BitOr => if let Ok(result) = lhs.bitor(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::BitLS => if let Ok(result) = lhs.shl(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::BitRS => if let Ok(result) = lhs.shr(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::NullishCoalescing => if lhs.is_null() { rhs } else { lhs }
                    Op::Gt => Value::Bool(lhs > rhs),
                    Op::Gte => Value::Bool(lhs >= rhs),
                    Op::Lt => Value::Bool(lhs < rhs),
                    Op::Lte => Value::Bool(lhs <= rhs),
                    Op::Eq => Value::Bool(lhs == rhs),
                    Op::Neq => Value::Bool(lhs != rhs),
                    Op::RangeOpen => if let Some(result) = build_range(lhs, rhs, false) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    Op::RangeClose => if let Some(result) = build_range(lhs, rhs, true) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Value::Undetermined
                    }
                    _ => unreachable!()
                }
            } else {
                Value::Undetermined
            }
        }
    }
}

fn build_range(lhs: Value, rhs: Value, closed: bool) -> Option<Value> {
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
        Some(Value::Range(Range {
            closed,
            start: Box::new(lhs),
            end: Box::new(rhs),
        }))
    } else {
        None
    }
}

fn resolve_unit<'a>(unit: &Unit, context: &'a ResolverContext<'a>, expected: &Type) -> Accessible {
    if unit.expressions.len() == 1 {
        resolve_expression_kind(unit.expressions.get(0).unwrap(), context, expected)
    } else {
        let expected = Type::Undetermined;
        let mut current = resolve_expression_kind(unit.expressions.get(0).unwrap(), context, &expected);
        if current.is_undetermined() {
            return current;
        } else {
            for (index, item) in unit.expressions.iter().enumerate() {
                if index == 0 { continue }
                match current {
                    Accessible::Value(current_value) => {
                        context.insert_diagnostics_error(item.span(), "Builtin instance fields and methods are not implemented yet");
                        current = Accessible::Value(Value::Undetermined)
                    }
                    Accessible::Reference(current_reference) => {
                        match context.schema.find_top_by_path(&current_reference.path).unwrap() {
                            Top::Config(config) => {
                                match item {
                                    ExpressionKind::Identifier(_) => todo!("return model field here"),
                                    ExpressionKind::ArgumentList(a) => {
                                        context.insert_diagnostics_error(a.span, "Config cannot be called");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    ExpressionKind::Call(c) => {
                                        context.insert_diagnostics_error(c.span, "Config cannot be called");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    ExpressionKind::Subscript(s) => {
                                        context.insert_diagnostics_error(s.span, "Config cannot be subscript");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    _ => unreachable!()
                                }
                            }
                            Top::Constant(constant) => {
                                if !constant.is_resolved() {
                                    resolve_constant(constant, context);
                                }
                                match item {
                                    ExpressionKind::Identifier(_) => todo!("return model field here"),
                                    ExpressionKind::ArgumentList(a) => {
                                        context.insert_diagnostics_error(a.span, "Constant cannot be called");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    ExpressionKind::Call(c) => {
                                        todo!("resolve and call");
                                    }
                                    ExpressionKind::Subscript(s) => {
                                        context.insert_diagnostics_error(s.span, "Constant cannot be subscript");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    _ => unreachable!()
                                }
                            }
                            Top::Enum(r#enum) => {
                                match item {
                                    ExpressionKind::Identifier(i) => {
                                        current = Accessible::Value(resolve_enum_variant_literal(&EnumVariantLiteral {
                                            span: Span::default(),
                                            identifier: i.clone(),
                                            argument_list: None,
                                        }, context, &Type::Enum(r#enum.path.clone())))
                                    }
                                    ExpressionKind::Call(c) => {
                                        current = Accessible::Value(resolve_enum_variant_literal(&EnumVariantLiteral {
                                            span: Span::default(),
                                            identifier: c.identifier.clone(),
                                            argument_list: None,
                                        }, context, &Type::Enum(r#enum.path.clone())))
                                    }
                                    ExpressionKind::ArgumentList(a) => {
                                        context.insert_diagnostics_error(a.span, "Enum cannot be called");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    ExpressionKind::Subscript(s) => {
                                        context.insert_diagnostics_error(s.span, "Enum cannot be subscript");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    _ => unreachable!()
                                }
                            }
                            Top::Model(_) => {
                                match item {
                                    ExpressionKind::Identifier(_) => todo!("return model field enum here"),
                                    ExpressionKind::ArgumentList(a) => {
                                        context.insert_diagnostics_error(a.span, "Model cannot be called");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    ExpressionKind::Call(c) => {
                                        context.insert_diagnostics_error(c.span, "Model cannot be called");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    ExpressionKind::Subscript(s) => {
                                        context.insert_diagnostics_error(s.span, "Model cannot be subscript");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    _ => unreachable!()
                                }
                            }
                            Top::Interface(_) => {
                                match item {
                                    ExpressionKind::Identifier(_) => todo!("return interface field enum here"),
                                    ExpressionKind::ArgumentList(a) => {
                                        context.insert_diagnostics_error(a.span, "Interface cannot be called");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    ExpressionKind::Call(c) => {
                                        context.insert_diagnostics_error(c.span, "Interface cannot be called");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    ExpressionKind::Subscript(s) => {
                                        context.insert_diagnostics_error(s.span, "Interface cannot be subscript");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    _ => unreachable!()
                                }
                            }
                            Top::Namespace(namespace) => {
                                match item {
                                    ExpressionKind::Identifier(identifier) => {
                                        if let Some(top) = namespace.find_top_by_name(identifier.name(), &top_filter_for_reference_type(ReferenceType::Default)) {
                                            current = Accessible::Reference(Reference {
                                                path: top.path().clone(),
                                                r#type: ReferenceType::Default,
                                            })
                                        } else {
                                            context.insert_diagnostics_error(identifier.span, "Invalid reference");
                                            return Accessible::Value(Value::Undetermined)
                                        }
                                    },
                                    ExpressionKind::Call(c) => {
                                        todo!("resolve and call")
                                    }
                                    ExpressionKind::ArgumentList(a) => {
                                        context.insert_diagnostics_error(a.span, "Namespace cannot be called");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    ExpressionKind::Subscript(s) => {
                                        context.insert_diagnostics_error(s.span, "Namespace cannot be subscript");
                                        return Accessible::Value(Value::Undetermined)
                                    }
                                    _ => unreachable!()
                                }
                            }
                            _ => unreachable!()
                        }
                    }
                }
            }
            current
        }
    }
}