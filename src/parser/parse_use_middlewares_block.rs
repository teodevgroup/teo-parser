use std::cell::RefCell;
use std::collections::BTreeMap;
use crate::ast::use_middlewares::UseMiddlewaresBlock;
use crate::availability::Availability;
use crate::{parse_insert_keyword, parse_set};
use crate::ast::middleware::MiddlewareType;
use crate::parser::parse_literals::parse_array_literal;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_use_middlewares_block(pair: Pair<'_>, context: &ParserContext) -> UseMiddlewaresBlock {
    let span = parse_span(&pair);
    let path = context.next_parent_path();
    let string_path = context.next_parent_string_path("useMiddlewares");
    let mut children = BTreeMap::new();
    let mut array_literal = 0;
    let mut middleware_type = MiddlewareType::HandlerMiddleware;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::REQUEST_KEYWORD => {
                middleware_type = MiddlewareType::RequestMiddleware;
                parse_insert_keyword!(context, current, children, "request");
            }
            Rule::HANDLER_KEYWORD => {
                middleware_type = MiddlewareType::HandlerMiddleware;
                parse_insert_keyword!(context, current, children, "handler");
            },
            Rule::MIDDLEWARES_KEYWORD => parse_insert_keyword!(context, current, children, "middlewares"),
            Rule::array_literal => parse_set!(parse_array_literal(current, context), children, array_literal),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    context.pop_string_path();
    UseMiddlewaresBlock {
        span,
        path,
        string_path,
        children,
        define_availability: context.current_availability_flag(),
        actual_availability: RefCell::new(Availability::none()),
        array_literal,
        middleware_type,
    }
}