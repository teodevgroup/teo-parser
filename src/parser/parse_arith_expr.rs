use std::cell::RefCell;
use crate::ast::arith_expr::{ArithExpr, BinaryOperation, Operator, UnaryOperation, UnaryPostfixOperation};
use crate::ast::expression::Expression;
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, EXPR_PRATT_PARSER, Rule};

pub(super) fn parse_arith_expr(pair: Pair<'_>, context: &mut ParserContext) -> ArithExpr {
    let span = parse_span(&pair);
    let result = EXPR_PRATT_PARSER.map_primary(|primary| match primary.as_rule() {
        Rule::operand => ArithExpr::Expression(Box::new(Expression { kind: parse_expression(primary, context), resolved: RefCell::new(None) })),
        _ => {
            context.insert_unparsed(parse_span(&primary));
            panic!("unreachable 3")
        },
    }).map_prefix(|op, rhs| {
        let op = match op.as_rule() {
            Rule::BI_NEG => Operator::BitNeg,
            Rule::NEG => Operator::Neg,
            Rule::NOT => Operator::Not,
            _ => panic!("unreachable 4"),
        };
        ArithExpr::UnaryOperation(UnaryOperation {
            span,
            op,
            rhs: Box::new(rhs),
        })
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
            _ => panic!("unreachable 5"),
        };
        ArithExpr::BinaryOperation(BinaryOperation {
            span,
            lhs: Box::new(lhs),
            op,
            rhs: Box::new(rhs),
        })
    }).map_postfix(|lhs, op| {
        let op = match op.as_rule() {
            Rule::FORCE_UNWRAP => Operator::ForceUnwrap,
            _ => panic!("unreachable 6"),
        };
        ArithExpr::UnaryPostfixOperation(UnaryPostfixOperation {
            span,
            lhs: Box::new(lhs),
            op,
        })
    }).parse(pair.into_inner());
    result
}