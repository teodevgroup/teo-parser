use std::default::Default;
use std::ops::{Add, BitAnd, BitOr, BitXor, Div, Mul, Neg, Not, Rem, Shl, Shr, Sub};
use maplit::{btreeset, hashmap, hashset};
use teo_teon::types::enum_variant::EnumVariant;
use teo_teon::types::range::Range;
use teo_teon::value::Value;
use crate::ast::accessible::Accessible;
use crate::ast::arith::{ArithExpr, Op};
use crate::ast::expr::{Expression, ExpressionKind};
use crate::ast::group::Group;
use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, EnumVariantLiteral, NullLiteral, NumericLiteral, RegExpLiteral, StringLiteral, TupleLiteral};
use crate::ast::type_expr::Type;
use crate::ast::reference::{Reference, ReferenceType};
use crate::ast::span::Span;
use crate::ast::top::Top;
use crate::ast::unit::Unit;
use crate::resolver::resolve_constant::resolve_constant;
use crate::resolver::resolve_identifier::{resolve_identifier};
use crate::resolver::resolve_pipeline::resolve_pipeline;
use crate::resolver::resolver_context::ResolverContext;
use crate::utils::top_filter::top_filter_for_reference_type;

pub(super) fn resolve_expression<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type) {
    expression.resolve(resolve_expression_kind(&expression.kind, context, expected))
}

pub(super) fn resolve_expression_and_unwrap_value<'a>(expression: &'a Expression, context: &'a ResolverContext<'a>, expected: &Type) {
    expression.resolve(Accessible::Type(resolve_expression_kind_and_unwrap_type(&expression.kind, context, expected)))
}

pub(super) fn resolve_expression_kind<'a>(expression: &'a ExpressionKind, context: &'a ResolverContext<'a>, expected: &Type) -> Accessible {
    match &expression {
        ExpressionKind::Group(e) => resolve_group(e, context, expected),
        ExpressionKind::ArithExpr(e) => Accessible::Type(resolve_arith_expr(e, context, expected)),
        ExpressionKind::NumericLiteral(n) => Accessible::Type(resolve_numeric_literal(n, context, expected)),
        ExpressionKind::StringLiteral(e) => Accessible::Type(resolve_string_literal(e, context, expected)),
        ExpressionKind::RegExpLiteral(e) => Accessible::Type(resolve_regexp_literal(e, context, expected)),
        ExpressionKind::BoolLiteral(b) => Accessible::Type(resolve_bool_literal(b, context, expected)),
        ExpressionKind::NullLiteral(n) => Accessible::Type(resolve_null_literal(n, context, expected)),
        ExpressionKind::EnumVariantLiteral(e) => Accessible::Type(resolve_enum_variant_literal(e, context, expected)),
        ExpressionKind::TupleLiteral(t) => Accessible::Type(resolve_tuple_literal(t, context, expected)),
        ExpressionKind::ArrayLiteral(a) => Accessible::Type(resolve_array_literal(a, context, expected)),
        ExpressionKind::DictionaryLiteral(d) => Accessible::Type(resolve_dictionary_literal(d, context, expected)),
        ExpressionKind::Identifier(i) => if let Some(reference) = resolve_identifier(i, context, ReferenceType::Default) {
            Accessible::Reference(reference.clone())
        } else {
            context.insert_diagnostics_error(i.span, "ReferenceError: undefined identifier");
            Accessible::Type(Type::Undetermined)
        }
        ExpressionKind::ArgumentList(_) => unreachable!(),
        ExpressionKind::Subscript(_) => unreachable!(),
        ExpressionKind::Unit(u) => resolve_unit(u, context, expected),
        ExpressionKind::Pipeline(p) => Accessible::Type(resolve_pipeline(p, context)),
        ExpressionKind::Call(_) => unreachable!(),
    }
}

pub(super) fn resolve_expression_kind_and_unwrap_type<'a>(expression: &'a ExpressionKind, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    let result = resolve_expression_kind(expression, context, expected);
    if result.is_reference() {
        // do things here to resolve
        Type::Undetermined
    } else {
        result.into_type().unwrap()
    }
}

fn resolve_group<'a>(group: &'a Group, context: &'a ResolverContext<'a>, expected: &Type) -> Accessible {
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
    Type::RegExp
}

fn resolve_bool_literal<'a>(r: &BoolLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    Type::Bool
}

fn resolve_null_literal<'a>(r: &NullLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    Type::Null
}

fn resolve_enum_variant_literal<'a>(e: &EnumVariantLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    if let Some(enum_path) = expected.enum_path() {
        let r#enum = context.schema.find_top_by_path(enum_path).unwrap().as_enum().unwrap();
        if let Some(member) = r#enum.members.iter().find(|m| m.identifier.name() == e.identifier.name()) {
            Type::Enum(enum_path.clone())
        } else {
            context.insert_diagnostics_error(e.span, "ValueError: undefined enum member");
            Type::Undetermined
        }
    } else {
        context.insert_diagnostics_error(e.span, "ValueError: unexpected enum variant literal");
        Type::Undetermined
    }
}

fn resolve_tuple_literal<'a>(t: &'a TupleLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    let types = expected.as_tuple();
    let mut retval = vec![];
    let undetermined = Type::Undetermined;
    for (i, e) in t.expressions.iter().enumerate() {
        retval.push(resolve_expression_kind_and_unwrap_type(e, context, types.map(|t| t.get(i)).flatten().unwrap_or(&undetermined)));
    }
    Type::Tuple(retval)
}

fn resolve_array_literal<'a>(a: &'a ArrayLiteral, context: &'a ResolverContext<'a>, expected: &Type) -> Type {
    let r#type = expected.as_array();
    let mut retval = hashset![];
    let undetermined = Type::Undetermined;
    for e in a.expressions.iter() {
        retval.insert(resolve_expression_kind_and_unwrap_type(e, context, r#type.unwrap_or(&undetermined)));
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
        let k_value = resolve_expression_kind_and_unwrap_type(k, context, &Type::String);
        if !k_value.is_string() {
            context.insert_diagnostics_error(k.span(), "ValueError: dictionary key is not String");
        }
        let v_value = resolve_expression_kind_and_unwrap_type(v, context, r#type);
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
        ArithExpr::Expression(e) => resolve_expression_kind_and_unwrap_type(e.as_ref(), context, expected),
        ArithExpr::UnaryOp(unary) => {
            let v = resolve_arith_expr(unary.rhs.as_ref(), context, expected);
            if !v.is_undetermined() {
                match unary.op {
                    Op::Neg => if let Ok(result) = v.neg() {
                        result
                    } else {
                        context.insert_diagnostics_error(unary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::Not => v.normal_not(),
                    Op::BitNeg => if let Ok(result) = v.not() {
                        result
                    } else {
                        context.insert_diagnostics_error(unary.span, "ValueError: invalid expression");
                        Type::Undetermined
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
                        Type::Undetermined
                    }
                    Op::Sub => if let Ok(result) = lhs.sub(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::Mul => if let Ok(result) = lhs.mul(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::Div => if let Ok(result) = lhs.div(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::Mod => if let Ok(result) = lhs.rem(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::And => if lhs.normal_not().as_bool().unwrap() { lhs } else { rhs }
                    Op::Or => if lhs.normal_not().as_bool().unwrap() { rhs } else { lhs }
                    Op::BitAnd => if let Ok(result) = lhs.bitand(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::BitXor => if let Ok(result) = lhs.bitxor(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::BitOr => if let Ok(result) = lhs.bitor(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::BitLS => if let Ok(result) = lhs.shl(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
                    }
                    Op::BitRS => if let Ok(result) = lhs.shr(&rhs) {
                        result
                    } else {
                        context.insert_diagnostics_error(binary.span, "ValueError: invalid expression");
                        Type::Undetermined
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
                        Type::Undetermined
                    }
                    Op::RangeClose => if let Some(result) = build_range(lhs, rhs, true) {
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

fn resolve_unit<'a>(unit: &'a Unit, context: &'a ResolverContext<'a>, expected: &Type) -> Accessible {
    if unit.expressions.len() == 1 {
        Accessible::Type(resolve_expression_kind_and_unwrap_type(unit.expressions.get(0).unwrap(), context, expected))
    } else {
        let expected = Type::Undetermined;
        let mut current = resolve_expression_kind(unit.expressions.get(0).unwrap(), context, &expected);
        if current.is_undetermined() {
            return current;
        } else {
            for (index, item) in unit.expressions.iter().enumerate() {
                if index == 0 { continue }
                current = resolve_current_item_for_unit(&current, item, context);
            }
            current
        }
    }
}

fn resolve_current_item_for_unit<'a>(current: &Accessible, item: &ExpressionKind, context: &'a ResolverContext<'a>) -> Accessible {
    match current {
        Accessible::Type(current_value) => {
            context.insert_diagnostics_error(item.span(), "Builtin instance fields and methods are not implemented yet");
            Accessible::Type(Type::Undetermined)

            // if current_value.is_reference() {
            //     resolve_current_item_for_unit(&Accessible::Reference(Reference {
            //         path: current_value.as_reference().unwrap().clone(),
            //         r#type: ReferenceType::Default,
            //     }), item, context)
            // } else {
            // }
        }
        Accessible::Reference(current_reference) => {
            match context.schema.find_top_by_path(&current_reference.path).unwrap() {
                Top::Config(config) => {
                    match item {
                        ExpressionKind::Identifier(identifier) => {
                            if let Some(item) = config.items.iter().find(|i| i.identifier.name() == identifier.name()) {
                                return item.expression.resolved().clone();
                            } else {
                                context.insert_diagnostics_error(item.span(), "Undefined field");
                                return Accessible::Type(Type::Undetermined)
                            }
                        },
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Config cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Call(c) => {
                            context.insert_diagnostics_error(c.span, "Config cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Config cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Constant(constant) => {
                    if !constant.is_resolved() {
                        resolve_constant(constant, context);
                    }
                    resolve_current_item_for_unit(&Accessible::Type(track_accessible_upwards(&current, context)), item, context)
                }
                Top::Enum(r#enum) => {
                    match item {
                        ExpressionKind::Identifier(i) => {
                            return Accessible::Type(resolve_enum_variant_literal(&EnumVariantLiteral {
                                span: Span::default(),
                                identifier: i.clone(),
                                argument_list: None,
                            }, context, &Type::Enum(r#enum.path.clone())))
                        }
                        ExpressionKind::Call(c) => {
                            return Accessible::Type(resolve_enum_variant_literal(&EnumVariantLiteral {
                                span: Span::default(),
                                identifier: c.identifier.clone(),
                                argument_list: None,
                            }, context, &Type::Enum(r#enum.path.clone())))
                        }
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Enum cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Enum cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Model(_) => {
                    match item {
                        ExpressionKind::Identifier(_) => todo!("return model field enum here"),
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Model cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Call(c) => {
                            context.insert_diagnostics_error(c.span, "Model cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Model cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Interface(_) => {
                    match item {
                        ExpressionKind::Identifier(_) => todo!("return interface field enum here"),
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Interface cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Call(c) => {
                            context.insert_diagnostics_error(c.span, "Interface cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Interface cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                Top::Namespace(namespace) => {
                    match item {
                        ExpressionKind::Identifier(identifier) => {
                            if let Some(top) = namespace.find_top_by_name(identifier.name(), &top_filter_for_reference_type(ReferenceType::Default)) {
                                return Accessible::Reference(Reference {
                                    path: top.path().clone(),
                                    r#type: ReferenceType::Default,
                                })
                            } else {
                                context.insert_diagnostics_error(identifier.span, "Invalid reference");
                                return Accessible::Type(Type::Undetermined)
                            }
                        },
                        ExpressionKind::Call(c) => {
                            todo!("resolve and call")
                        }
                        ExpressionKind::ArgumentList(a) => {
                            context.insert_diagnostics_error(a.span, "Namespace cannot be called");
                            return Accessible::Type(Type::Undetermined)
                        }
                        ExpressionKind::Subscript(s) => {
                            context.insert_diagnostics_error(s.span, "Namespace cannot be subscript");
                            return Accessible::Type(Type::Undetermined)
                        }
                        _ => unreachable!()
                    }
                }
                _ => unreachable!()
            }
        }
    }
}

fn track_accessible_upwards<'a>(accessible: &Accessible, context: &'a ResolverContext<'a>) -> Value {
    match accessible {
        Accessible::Type(v) => v.clone(),
        Accessible::Reference(r) => {
            let top = context.schema.find_top_by_path(&r.path).unwrap();
            match top {
                Top::Config(c) => Value::Reference(c.path.clone()),
                Top::Constant(c) => {
                    if !c.is_resolved() {
                        resolve_constant(c, context);
                    }
                    track_accessible_upwards(&c.resolved().accessible, context)
                }
                Top::Enum(e) => Value::Reference(e.path.clone()),
                Top::Model(m) => Value::Reference(m.path.clone()),
                Top::Interface(i) => Value::Reference(i.path.clone()),
                Top::Namespace(n) => Value::Reference(n.path.clone()),
                _ => unreachable!(),
            }

        }
    }
}