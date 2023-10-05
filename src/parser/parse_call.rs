use crate::ast::call::Call;
use crate::parser::parse_argument::parse_argument_list;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_call(pair: Pair<'_>, context: &mut ParserContext) -> Call {
    let span = parse_span(&pair);
    let mut identifier = None;
    let mut argument_list = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::argument_list => argument_list = Some(parse_argument_list(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Call { span, identifier: identifier.unwrap(), argument_list: argument_list.unwrap() }
}