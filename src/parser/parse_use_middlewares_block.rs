use crate::ast::use_middlewares::UseMiddlewaresBlock;
use crate::parser::parse_literals::parse_array_literal;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_use_middlewares_block(pair: Pair<'_>, context: &mut ParserContext) -> UseMiddlewaresBlock {
    let span = parse_span(&pair);
    let path = context.next_path();
    let mut array_literal = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::MIDDLEWARES_KEYWORD => (),
            Rule::array_literal => array_literal = Some(parse_array_literal(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    UseMiddlewaresBlock {
        span,
        path,
        array_literal: array_literal.unwrap()
    }
}