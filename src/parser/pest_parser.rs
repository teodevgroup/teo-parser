use pest::pratt_parser::PrattParser;
use once_cell::sync::Lazy;

#[derive(pest_derive::Parser)]
#[grammar = "./src/parser/schema.pest"]
pub(super) struct SchemaParser;

pub(super) type Pair<'a> = pest::iterators::Pair<'a, Rule>;

pub(super) static EXPR_PRATT_PARSER: Lazy<PrattParser<Rule>> = Lazy::new(|| {
    use pest::pratt_parser::{Assoc::*, Op};
    use Rule::*;

    // Precedence is defined lowest to highest
    PrattParser::new()
        // Addition and subtract have equal precedence
        .op(Op::infix(NULLISH_COALESCING, Left))
        .op(Op::infix(OR, Left))
        .op(Op::infix(AND, Left))
        .op(Op::infix(LT, Left) | Op::infix(GT, Left) | Op::infix(LTE, Left) | Op::infix(GTE, Left) | Op::infix(EQ, Left) | Op::infix(NEQ, Left))
        .op(Op::infix(BI_OR, Left))
        .op(Op::infix(BI_XOR, Left))
        .op(Op::infix(BI_AND, Left))
        .op(Op::infix(BI_LS, Left) | Op::infix(BI_RS, Left))
        .op(Op::infix(ADD, Left) | Op::infix(SUB, Left))
        .op(Op::infix(MUL, Left) | Op::infix(DIV, Left) | Op::infix(MOD, Left))
        .op(Op::prefix(NOT))
        .op(Op::prefix(BI_NEG))
        .op(Op::prefix(NEG))
});

pub(super) static TYPE_PRATT_PARSER: Lazy<PrattParser<Rule>> = Lazy::new(|| {
    use pest::pratt_parser::{Assoc::*, Op};
    use Rule::*;

    // Precedence is defined lowest to highest
    PrattParser::new()
        // Addition and subtract have equal precedence
        .op(Op::infix(BI_OR, Left))
});