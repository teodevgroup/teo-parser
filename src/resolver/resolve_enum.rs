use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use maplit::btreemap;
use teo_teon::value::Value;
use crate::ast::arith::{ArithExpr, Op};
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::r#enum::{Enum, EnumMember, EnumMemberExpression, EnumMemberResolved, EnumResolved};
use crate::ast::reference::ReferenceType;
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolver_context::ResolverContext;

pub(super) fn resolve_enum<'a>(r#enum: &'a Enum, context: &'a ResolverContext<'a>) {
    if r#enum.is_resolved() {
        return
    }
    r#enum.resolve(EnumResolved {
        actual_availability: context.current_availability()
    });
    if context.has_examined_default_path(&r#enum.string_path, r#enum.define_availability) {
        context.insert_duplicated_identifier(r#enum.identifier.span);
    }
    context.clear_examined_fields();
    // decorators
    for decorator in &r#enum.decorators {
        resolve_decorator(decorator, context, &btreemap!{}, ReferenceType::EnumDecorator);
    }
    // members
    let option_member_map = Mutex::new(btreemap!{});
    for (index, member) in r#enum.members.iter().enumerate() {
        resolve_enum_member(member, context, r#enum.option, index, &option_member_map);
    }
    context.add_examined_default_path(r#enum.string_path.clone(), r#enum.define_availability);
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
        resolve_decorator(decorator, context, &btreemap!{}, ReferenceType::EnumMemberDecorator)
    }
    // expression
    if let Some(member_expression) = &member.expression {
        if option {
            match member_expression {
                EnumMemberExpression::StringLiteral(s) => {
                    member.resolve(EnumMemberResolved { value: Value::Int(1 << index), actual_availability: context.current_availability() });
                    context.insert_diagnostics_error(
                        member_expression.span(),
                        "EnumMemberError: Option value expression should be numeric or defined member expression"
                    )
                },
                EnumMemberExpression::NumericLiteral(n) => {
                    let value = n.value.as_int().unwrap();
                    member.resolve(EnumMemberResolved { value: Value::Int(value), actual_availability: context.current_availability() });
                    map.lock().unwrap().insert(member.identifier.name(), value);
                },
                EnumMemberExpression::ArithExpr(expr) => {
                    let value = resolve_enum_member_expr(expr, context, map);
                    member.resolve(EnumMemberResolved { value: Value::Int(value), actual_availability: context.current_availability() });
                    map.lock().unwrap().insert(member.identifier.name(), value);
                }
            }
        } else {
            match member_expression.as_string_literal() {
                Some(s) => member.resolve(EnumMemberResolved { value: Value::String(s.value.clone()), actual_availability: context.current_availability() }),
                None => {
                    member.resolve(EnumMemberResolved { value: Value::String(member.identifier.name.clone()), actual_availability: context.current_availability() });
                    context.insert_diagnostics_error(
                        member_expression.span(),
                        "EnumMemberError: Enum value expression should be string literal"
                    )
                }
            }
        }
    } else {
        if option {
            member.resolve(EnumMemberResolved { value: Value::Int(1 << index), actual_availability: context.current_availability() });
        } else {
            member.resolve(EnumMemberResolved { value: Value::String(member.identifier.name.clone()), actual_availability: context.current_availability() });
        }
    }
    // argument list
    if let Some(argument_list_declaration) = &member.argument_list_declaration {
        resolve_argument_list_declaration(argument_list_declaration, &vec![], &vec![], context, member.define_availability);
    }
}

fn resolve_enum_member_expression<'a>(expression: &Expression, context: &ResolverContext<'a>, map: &Mutex<BTreeMap<&'a str, i32>>) -> i32 {
    match &expression.kind {
        ExpressionKind::Unit(u) => if u.expressions.len() == 1 {
            resolve_enum_member_expression(u.expressions.get(0).unwrap(), context, map)
        } else {
            context.insert_diagnostics_error(expression.span(), "EnumMemberError: Only number literals and enum variant literals are allowed");
            0
        },
        ExpressionKind::NumericLiteral(n) => n.value.as_int().unwrap(),
        ExpressionKind::Group(g) => resolve_enum_member_expression(g.expression.as_ref(), context, map),
        ExpressionKind::EnumVariantLiteral(e) => if let Some(v) = map.lock().unwrap().get(e.identifier.name()) {
            *v
        } else {
            context.insert_diagnostics_error(e.span, "EnumMemberError: Enum member is not defined");
            0
        },
        _ => {
            context.insert_diagnostics_error(expression.span(), "only number literals and enum variant literals are allowed");
            0
        }
    }
}

fn resolve_enum_member_expr<'a>(expr: &'a ArithExpr, context: &ResolverContext<'a>, map: &Mutex<BTreeMap<&'a str, i32>>) -> i32 {
    match expr {
        ArithExpr::Expression(expression) => {
            resolve_enum_member_expression(expression, context, map)
        },
        ArithExpr::BinaryOp(bi_op) => {
            let lhs = resolve_enum_member_expr(bi_op.lhs.as_ref(), context, map);
            let rhs = resolve_enum_member_expr(bi_op.rhs.as_ref(), context, map);
            match bi_op.op {
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
                    context.insert_diagnostics_error(bi_op.span, "this binary operation is not allowed in enum member definition");
                    0
                }
            }
        }
        ArithExpr::UnaryOp(u_op) => {
            let rhs = resolve_enum_member_expr(u_op.rhs.as_ref(), context, map);
            match u_op.op {
                Op::Neg => -rhs,
                Op::Not => if rhs == 0 { 1 } else { 0 }
                Op::BitNeg => !rhs,
                _ => {
                    context.insert_diagnostics_error(u_op.span, "this unary operation is not allowed in enum member definition");
                    0
                }
            }
        }
        ArithExpr::UnaryPostfixOp(u_postfix_op) => {
            context.insert_diagnostics_error(u_postfix_op.span, "force unwrap is not allowed in enum member definition");
            0
        }
    }
}