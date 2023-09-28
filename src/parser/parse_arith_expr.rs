use crate::ast::arith::{ArithExpr, BinaryOp, Op};
use crate::parser::parse_expression::parse_expression_kind;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, PRATT_PARSER, Rule};

pub(super) fn parse_arith_expr(pair: Pair<'_>, context: &mut ParserContext) -> ArithExpr {
    let span = parse_span(&pair);
    PRATT_PARSER.map_primary(|primary| match primary.as_rule() {
        Rule::operand => ArithExpr::Expression(Box::new(parse_expression_kind(primary, context))),
        _ => {
            context.insert_unparsed(parse_span(&primary));
            unreachable!()
        },
    }).map_infix(|lhs, op, rhs| {
        let op = match op.as_rule() {
            Rule::ADD => Op::Add,
            Rule::SUB => Op::Sub,
            Rule::MUL => Op::Mul,
            Rule::DIV => Op::Div,
            Rule::MOD => Op::Mod,
            Rule::NEG => Op::Neg,
            Rule::BI_AND => Op::BitAnd,
            Rule::BI_XOR => Op::BitXor,
            Rule::BI_OR => Op::BitOr,
            Rule::BI_NEG => Op::BitNeg,
            Rule::NULLISH_COALESCING => Op::NullishCoalescing,
            _ => unreachable!(),
        };
        ArithExpr::BinaryOp(BinaryOp {
            span,
            lhs: Box::new(lhs),
            op,
            rhs: Box::new(rhs),
        })
    }).parse(pair.into_inner())
}