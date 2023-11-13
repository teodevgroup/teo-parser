use std::cell::RefCell;
use crate::ast::arith_expr::{ArithExpr, BinaryOperation, Operator, UnaryOperation, UnaryPostfixOperation};
use crate::ast::expression::Expression;
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup};
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, EXPR_PRATT_PARSER, Rule};
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_arith_expr(pair: Pair<'_>, context: &mut ParserContext) -> ArithExpr {
    let span = parse_span(&pair);
    let result = EXPR_PRATT_PARSER.map_primary(|primary| match primary.as_rule() {
        Rule::operand => {
            let expression = parse_expression(primary, context);
            ArithExpr::Expression(Box::new(expression))
        },
        _ => {
            context.insert_unparsed(parse_span(&primary));
            unreachable!()
        },
    }).map_prefix(|op, rhs| {
        let op = match op.as_rule() {
            Rule::BI_NEG => Operator::BitNeg,
            Rule::NEG => Operator::Neg,
            Rule::NOT => Operator::Not,
            _ => unreachable!(),
        };
        parse_container_node_variables!();
        children.insert(rhs.id(), rhs.into());
        let operation = UnaryOperation {
            span,
            path,
            children,
            op,
            rhs: rhs.id(),
        };
        parse_container_node_variables_cleanup!();
        ArithExpr::UnaryOperation(operation)
    }).map_infix(|lhs, op, rhs| {
        let op = match op.as_rule() {
            Rule::ADD => Operator::Add,
            Rule::SUB => Operator::Sub,
            Rule::MUL => Operator::Mul,
            Rule::DIV => Operator::Div,
            Rule::MOD => Operator::Mod,
            Rule::BI_AND => Operator::BitAnd,
            Rule::BI_XOR => Operator::BitXor,
            Rule::BI_OR => Operator::BitOr,
            Rule::NULLISH_COALESCING => Operator::NullishCoalescing,
            Rule::BI_LS => Operator::BitLS,
            Rule::BI_RS => Operator::BitRS,
            Rule::AND => Operator::And,
            Rule::OR => Operator::Or,
            Rule::GT => Operator::Gt,
            Rule::GTE => Operator::Gte,
            Rule::LT => Operator::Lt,
            Rule::LTE => Operator::Lte,
            Rule::EQ => Operator::Eq,
            Rule::NEQ => Operator::Neq,
            Rule::RANGE_CLOSE => Operator::RangeClose,
            Rule::RANGE_OPEN => Operator::RangeOpen,
            _ => unreachable!(),
        };
        parse_container_node_variables!();
        children.insert(lhs.id(), lhs.into());
        children.insert(rhs.id(), rhs.into());
        let operation = BinaryOperation {
            span,
            path,
            children,
            op,
            lhs: lhs.id(),
            rhs: rhs.id(),
        };
        parse_container_node_variables_cleanup!();
        ArithExpr::BinaryOperation(operation)
    }).map_postfix(|lhs, op| {
        let op = match op.as_rule() {
            Rule::FORCE_UNWRAP => Operator::ForceUnwrap,
            _ => unreachable!(),
        };
        parse_container_node_variables!();
        children.insert(lhs.id(), lhs.into());
        let operation = UnaryPostfixOperation {
            span,
            path,
            children,
            op,
            lhs: lhs.id(),
        };
        parse_container_node_variables_cleanup!();
        ArithExpr::UnaryPostfixOperation(operation)
    }).parse(pair.into_inner());
    result
}