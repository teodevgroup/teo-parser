use crate::ast::middleware::Middleware;
use crate::parser::parse_argument_list_declaration::parse_argument_list_declaration;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_middleware(pair: Pair<'_>, context: &mut ParserContext) -> Middleware {
    let span = parse_span(&pair);
    let path = context.next_path();
    let mut identifier = None;
    let mut argument_list_declaration = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::argument_list_declaration => argument_list_declaration = Some(parse_argument_list_declaration(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Middleware {
        span,
        path,
        identifier: identifier.unwrap(),
        argument_list_declaration,
    }
}
