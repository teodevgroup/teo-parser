use std::collections::BTreeMap;

use std::sync::Mutex;
use maplit::btreemap;
use teo_teon::value::Value;
use crate::ast::arith_expr::{ArithExpr, ArithExprOperator};
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::r#enum::{Enum, EnumMember};
use crate::ast::reference_space::ReferenceSpace;
use crate::resolver::resolve_argument_list_declaration::resolve_argument_list_declaration;
use crate::resolver::resolve_decorator::resolve_decorator;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_enum_types<'a>(r#enum: &'a Enum, context: &'a ResolverContext<'a>) {
    *r#enum.actual_availability.borrow_mut() = context.current_availability();
    if context.has_examined_default_path(&r#enum.string_path, r#enum.define_availability) {
        context.insert_duplicated_identifier(r#enum.identifier().span());
    }
    context.clear_examined_fields();
    // decorators
    for decorator in r#enum.decorators() {
        resolve_decorator(decorator, context, &btreemap!{}, ReferenceSpace::EnumDecorator);
    }
    // members
    let option_member_map = Mutex::new(btreemap!{});
    for (index, member) in r#enum.members().enumerate() {
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
    for decorator in member.decorators() {
        resolve_decorator(decorator, context, &btreemap!{}, ReferenceSpace::EnumMemberDecorator)
    }
    // expression
    if let Some(member_expression) = member.expression() {
        if option {
            match &member_expression.kind {
                ExpressionKind::StringLiteral(_s) => {
                    member.resolve(Value::Int(1 << index));
                    context.insert_diagnostics_error(
                        member_expression.span(),
                        "EnumMemberError: Option expr expression should be numeric or defined member expression"
                    )
                },
                ExpressionKind::NumericLiteral(n) => {
                    let value = n.value.as_int().unwrap();
                    member.resolve(Value::Int(value));
                    map.lock().unwrap().insert(member.identifier().name(), value);
                },
                ExpressionKind::ArithExpr(expr) => {
                    let value = resolve_enum_member_expr(expr, context, map);
                    member.resolve(Value::Int(value));
                    map.lock().unwrap().insert(member.identifier().name(), value);
                }
                _ => unreachable!()
            }
        } else {
            match member_expression.kind.as_string_literal() {
                Some(s) => member.resolve(Value::String(s.value.clone())),
                None => {
                    member.resolve(Value::String(member.identifier().name().to_owned()));
                    context.insert_diagnostics_error(
                        member_expression.span(),
                        "EnumMemberError: Enum expr expression should be string literal"
                    )
                }
            }
        }
    } else {
        if option {
            member.resolve(Value::Int(1 << index));
        } else {
            member.resolve(Value::String(member.identifier().name().to_owned()));
        }
    }
    // argument list
    if let Some(argument_list_declaration) = member.argument_list_declaration() {
        resolve_argument_list_declaration(argument_list_declaration, &vec![], &vec![], context, member.define_availability);
    }
}

fn resolve_enum_member_expression<'a>(expression: &Expression, context: &ResolverContext<'a>, map: &Mutex<BTreeMap<&'a str, i32>>) -> i32 {
    match &expression.kind {
        ExpressionKind::Unit(u) => if u.expressions.len() == 1 {
            resolve_enum_member_expression(u.expressions().next().unwrap(), context, map)
        } else {
            context.insert_diagnostics_error(expression.span(), "EnumMemberError: Only number literals and enum variant literals are allowed");
            0
        },
        ExpressionKind::NumericLiteral(n) => n.value.as_int().unwrap(),
        ExpressionKind::Group(g) => resolve_enum_member_expression(g.expression(), context, map),
        ExpressionKind::EnumVariantLiteral(e) => if let Some(v) = map.lock().unwrap().get(e.identifier().name()) {
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
            let lhs = resolve_enum_member_expr(bi_op.lhs(), context, map);
            let rhs = resolve_enum_member_expr(bi_op.rhs(), context, map);
            match bi_op.op {
                ArithExprOperator::Add => lhs + rhs,
                ArithExprOperator::Sub => lhs - rhs,
                ArithExprOperator::Mul => lhs * rhs,
                ArithExprOperator::Div => lhs / rhs,
                ArithExprOperator::Mod => lhs & rhs,
                ArithExprOperator::And => if lhs == 0 { lhs } else { rhs },
                ArithExprOperator::Or | ArithExprOperator::NullishCoalescing => if lhs != 0 { lhs } else { rhs },
                ArithExprOperator::BitAnd => lhs & rhs,
                ArithExprOperator::BitXor => lhs ^ rhs,
                ArithExprOperator::BitOr => lhs | rhs,
                ArithExprOperator::BitLS => lhs << rhs,
                ArithExprOperator::BitRS => lhs >> rhs,
                ArithExprOperator::Gt => if lhs > rhs { 1 } else { 0 },
                ArithExprOperator::Gte => if lhs >= rhs { 1 } else { 0 },
                ArithExprOperator::Lt => if lhs < rhs { 1 } else { 0 },
                ArithExprOperator::Lte => if lhs <= rhs { 1 } else { 0 },
                ArithExprOperator::Eq => if lhs == rhs { 1 } else { 0 },
                ArithExprOperator::Neq => if lhs != rhs { 1 } else { 0 },
                _ => {
                    context.insert_diagnostics_error(bi_op.span, "this binary operation is not allowed in enum member definition");
                    0
                }
            }
        }
        ArithExpr::UnaryOperation(u_op) => {
            let rhs = resolve_enum_member_expr(u_op.rhs(), context, map);
            match u_op.op {
                ArithExprOperator::Neg => -rhs,
                ArithExprOperator::Not => if rhs == 0 { 1 } else { 0 }
                ArithExprOperator::BitNeg => !rhs,
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