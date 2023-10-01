use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use maplit::btreemap;
use teo_teon::value::Value;
use crate::ast::arith::{ArithExpr, Op};
use crate::ast::expr::ExpressionKind;
use crate::ast::r#enum::{Enum, EnumMember, EnumMemberExpression, EnumMemberResolved};
use crate::ast::reference::ReferenceType;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_enum<'a>(r#enum: &'a Enum, context: &'a ResolverContext<'a>) {
    if r#enum.resolved.load(Ordering::SeqCst) {
        return
    }
    if context.has_examined_default_path(&r#enum.string_path) {
        context.insert_duplicated_enum_error(r#enum);
    }
    context.clear_examined_fields();
    // decorators
    for decorator in &r#enum.decorators {
        resolve_decorator(decorator, context, ReferenceType::EnumDecorator);
    }
    // members
    let option_member_map = Mutex::new(btreemap!{});
    for (index, member) in r#enum.members.iter().enumerate() {
        resolve_enum_member(member, context, r#enum.option, index, &option_member_map);
    }
    context.add_examined_default_path(r#enum.string_path.clone());
    r#enum.resolved.store(true, Ordering::SeqCst);
}

pub(super) fn resolve_enum_member<'a>(
    member: &'a EnumMember,
    context: &'a ResolverContext<'a>,
    option: bool,
    index: usize,
    map: &Mutex<BTreeMap<&'a str, i32>>,
) {
    // decorators
    for decorator in &member.decorators {
        resolve_decorator(decorator, context, ReferenceType::EnumMemberDecorator)
    }
    // expression
    if let Some(member_expression) = &member.expression {
        if option {
            match member_expression {
                EnumMemberExpression::StringLiteral(s) => {
                    member.resolve(EnumMemberResolved::new(Value::I32(1 << index)));
                    context.insert_diagnostics_error(
                        member_expression.span(),
                        "EnumMemberError: Option value expression should be numeric or defined member expression"
                    )
                },
                EnumMemberExpression::NumericLiteral(n) => {
                    let value = n.value.as_i32().unwrap();
                    member.resolve(EnumMemberResolved::new(Value::I32(value)));
                    map.lock().unwrap().insert(member.identifier.name(), value);
                },
                EnumMemberExpression::ArithExpr(expr) => {
                    let value = resolve_enum_member_expr(expr, context, map);
                    member.resolve(EnumMemberResolved::new(Value::I32(value)));
                    map.lock().unwrap().insert(member.identifier.name(), value);
                }
            }
        } else {
            match member_expression.as_string_literal() {
                Some(s) => member.resolve(EnumMemberResolved::new(Value::String(s.value.clone()))),
                None => {
                    member.resolve(EnumMemberResolved::new(Value::String(member.identifier.name.clone())));
                    context.insert_diagnostics_error(
                        member_expression.span(),
                        "EnumMemberError: Enum value expression should be string literal"
                    )
                }
            }
        }
    } else {
        if option {
            member.resolve(EnumMemberResolved::new(Value::I32(1 << index)));
        } else {
            member.resolve(EnumMemberResolved::new(Value::String(member.identifier.name.clone())))
        }
    }
}

fn resolve_enum_member_expression<'a>(expression: &ExpressionKind, context: &ResolverContext<'a>, map: &Mutex<BTreeMap<&'a str, i32>>) -> i32 {
    match expression {
        ExpressionKind::Unit(u) => if u.expressions.len() == 1 {
            resolve_enum_member_expression(u.expressions.get(0).unwrap(), context, map)
        } else {
            context.insert_diagnostics_error(expression.span(), "EnumMemberError: Only number literals and enum variant literals are allowed");
            0
        },
        ExpressionKind::NumericLiteral(n) => n.value.as_i32().unwrap(),
        ExpressionKind::Group(g) => resolve_enum_member_expression(g.expression.as_ref(), context, map),
        ExpressionKind::EnumVariantLiteral(e) => if let Some(v) = map.lock().unwrap().get(e.value.as_str()) {
            *v
        } else {
            context.insert_diagnostics_error(e.span, "EnumMemberError: Enum member is not defined");
            0
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "EnumMemberError: Only number literals and enum variant literals are allowed");
            0
        }
    }
}

fn resolve_enum_member_expr<'a>(expr: &'a ArithExpr, context: &ResolverContext<'a>, map: &Mutex<BTreeMap<&'a str, i32>>) -> i32 {
    match expr {
        ArithExpr::Expression(expression) => {
            resolve_enum_member_expression(expression, context, map)
        },
        ArithExpr::BinaryOp(biOp) => {
            let lhs = resolve_enum_member_expr(biOp.lhs.as_ref(), context, map);
            let rhs = resolve_enum_member_expr(biOp.rhs.as_ref(), context, map);
            match biOp.op {
                Op::Add => lhs + rhs,
                Op::Sub => lhs - rhs,
                Op::Mul => lhs * rhs,
                Op::Div => lhs / rhs,
                Op::Mod => lhs & rhs,
                Op::And => if lhs == 0 { lhs } else { rhs },
                Op::Or | Op::NullishCoalescing => if lhs != 0 { lhs } else { rhs },
                Op::BitAnd => lhs & rhs,
                Op::BitXor => lhs ^ rhs,
                Op::BitOr => lhs | rhs,
                Op::BitLS => lhs << rhs,
                Op::BitRS => lhs >> rhs,
                Op::Gt => if lhs > rhs { 1 } else { 0 },
                Op::Gte => if lhs >= rhs { 1 } else { 0 },
                Op::Lt => if lhs < rhs { 1 } else { 0 },
                Op::Lte => if lhs <= rhs { 1 } else { 0 },
                Op::Eq => if lhs == rhs { 1 } else { 0 },
                Op::Neq => if lhs != rhs { 1 } else { 0 },
                _ => {
                    context.insert_diagnostics_error(biOp.span, "EnumMemberError: This binary operation is not allowed in enum member definition");
                    0
                }
            }
        }
        ArithExpr::UnaryOp(uOp) => {
            let rhs = resolve_enum_member_expr(uOp.rhs.as_ref(), context, map);
            match uOp.op {
                Op::Neg => -rhs,
                Op::Not => if rhs == 0 { 1 } else { 0 }
                Op::BitNeg => !rhs,
                _ => {
                    context.insert_diagnostics_error(uOp.span, "EnumMemberError: This unary operation is not allowed in enum member definition");
                    0
                }
            }
        }
    }
}