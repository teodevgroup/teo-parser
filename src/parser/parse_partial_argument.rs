use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_set};
use crate::ast::partial_argument::PartialArgument;
use crate::ast::punctuations::Punctuation;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_partial_argument(pair: Pair<'_>, context: &ParserContext) -> PartialArgument {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut name = 0;
    let mut colon = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON => parse_set!(Punctuation::new(":", parse_span(&current), context.next_path()), children, colon),
            Rule::identifier => parse_set!(parse_identifier(&current, context), children, name),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    PartialArgument {
        span,
        children,
        path,
        name,
        colon,
    }
}
