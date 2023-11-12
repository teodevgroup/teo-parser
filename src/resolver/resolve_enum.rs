use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use maplit::btreemap;
use teo_teon::value::Value;
use crate::ast::arith_expr::{ArithExpr, Operator};
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::r#enum::{Enum, EnumMember};
use crate::ast::reference_space::ReferenceSpace;
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_enum<'a>(r#enum: &'a Enum, context: &'a ResolverContext<'a>) {
    *r#enum.actual_availability.borrow_mut() = context.current_availability();
    if context.has_examined_default_path(&r#enum.string_path, r#enum.define_availability) {
        context.insert_duplicated_identifier(r#enum.identifier.span);
    }
    context.clear_examined_fields();
    // decorators
    for decorator in &r#enum.decorators {
        resolve_decorator(decorator, context, &btreemap!{}, ReferenceSpace::EnumDecorator);
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
    *member.actual_availability.borrow_mut() = context.current_availability();
    // decorators
    for decorator in &member.decorators {
        resolve_decorator(decorator, context, &btreemap!{}, ReferenceSpace::EnumMemberDecorator)
    }
    // expression
    if let Some(member_expression) = &member.expression {
        if option {
            match member_expression {
                EnumMemberExpression::StringLiteral(s) => {
                    member.resolve(EnumMemberResolved { value: Value::Int(1 << index) });
                    context.insert_diagnostics_error(
                        member_expression.span(),
                        "EnumMemberError: Option value expression should be numeric or defined member expression"
                    )
                },
                EnumMemberExpression::NumericLiteral(n) => {
                    let value = n.value.as_int().unwrap();
                    member.resolve(EnumMemberResolved { value: Value::Int(value) });
                    map.lock().unwrap().insert(member.identifier.name(), value);
                },
                EnumMemberExpression::ArithExpr(expr) => {
                    let value = resolve_enum_member_expr(expr, context, map);
                    member.resolve(EnumMemberResolved { value: Value::Int(value) });
                    map.lock().unwrap().insert(member.identifier.name(), value);
                }
            }
        } else {
            match member_expression.as_string_literal() {
                Some(s) => member.resolve(EnumMemberResolved { value: Value::String(s.value.clone()) }),
                None => {
                    member.resolve(EnumMemberResolved { value: Value::String(member.identifier.name.clone()) });
                    context.insert_diagnostics_error(
                        member_expression.span(),
                        "EnumMemberError: Enum value expression should be string literal"
                    )
                }
            }
        }
    } else {
        if option {
            member.resolve(EnumMemberResolved { value: Value::Int(1 << index) });
        } else {
            member.resolve(EnumMemberResolved { value: Value::String(member.identifier.name.clone()) });
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
        ArithExpr::BinaryOperation(bi_op) => {
            let lhs = resolve_enum_member_expr(bi_op.lhs.as_ref(), context, map);
            let rhs = resolve_enum_member_expr(bi_op.rhs.as_ref(), context, map);
            match bi_op.op {
                Operator::Add => lhs + rhs,
                Operator::Sub => lhs - rhs,
                Operator::Mul => lhs * rhs,
                Operator::Div => lhs / rhs,
                Operator::Mod => lhs & rhs,
                Operator::And => if lhs == 0 { lhs } else { rhs },
                Operator::Or | Operator::NullishCoalescing => if lhs != 0 { lhs } else { rhs },
                Operator::BitAnd => lhs & rhs,
                Operator::BitXor => lhs ^ rhs,
                Operator::BitOr => lhs | rhs,
                Operator::BitLS => lhs << rhs,
                Operator::BitRS => lhs >> rhs,
                Operator::Gt => if lhs > rhs { 1 } else { 0 },
                Operator::Gte => if lhs >= rhs { 1 } else { 0 },
                Operator::Lt => if lhs < rhs { 1 } else { 0 },
                Operator::Lte => if lhs <= rhs { 1 } else { 0 },
                Operator::Eq => if lhs == rhs { 1 } else { 0 },
                Operator::Neq => if lhs != rhs { 1 } else { 0 },
                _ => {
                    context.insert_diagnostics_error(bi_op.span, "this binary operation is not allowed in enum member definition");
                    0
                }
            }
        }
        ArithExpr::UnaryOperation(u_op) => {
            let rhs = resolve_enum_member_expr(u_op.rhs.as_ref(), context, map);
            match u_op.op {
                Operator::Neg => -rhs,
                Operator::Not => if rhs == 0 { 1 } else { 0 }
                Operator::BitNeg => !rhs,
                _ => {
                    context.insert_diagnostics_error(u_op.span, "this unary operation is not allowed in enum member definition");
                    0
                }
            }
        }
        ArithExpr::UnaryPostfixOperation(u_postfix_op) => {
            context.insert_diagnostics_error(u_postfix_op.span, "force unwrap is not allowed in enum member definition");
            0
        }
    }
}