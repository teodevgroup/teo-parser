use snailquote::unescape;
use crate::ast::literals::StringLiteral;
use crate::parser::parse_span::parse_span;
use crate::parser::pest_parser::Pair;

pub(super) fn parse_string_literal(pair: &Pair<'_>) -> StringLiteral {
    let span = parse_span(&pair);
    StringLiteral {
        value: unescape(pair.as_str()).unwrap(),
        span,
    }
}