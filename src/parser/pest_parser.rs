use pest::Parser as PestParser;
use pest::pratt_parser::PrattParser;
use once_cell::sync::Lazy;

#[derive(pest_derive::Parser)]
#[grammar = "./src/parser/schema.pest"]
pub(super) struct SchemaParser;

pub(super) type Pair<'a> = pest::iterators::Pair<'a, Rule>;

pub(super) static PRATT_PARSER: Lazy<PrattParser<Rule>> = Lazy::new(|| {
    use pest::pratt_parser::{Assoc::*, Op};
    use Rule::*;

    // Precedence is defined lowest to highest
    PrattParser::new()
        // Addition and subtract have equal precedence
        .op(Op::infix(BI_OR, Left))
        .op(Op::infix(BI_XOR, Left))
        .op(Op::infix(BI_AND, Left))
        .op(Op::infix(ADD, Left) | Op::infix(SUB, Left))
        .op(Op::infix(MUL, Left) | Op::infix(DIV, Left) | Op::infix(MOD, Left))
        .op(Op::prefix(BI_NEG))
        .op(Op::prefix(NEG))
});