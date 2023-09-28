use crate::ast::argument::Argument;
use crate::ast::argument_list::ArgumentList;
use crate::ast::expr::{Expression, ExpressionKind};
use crate::ast::identifier::Identifier;
use crate::ast::literals::NullLiteral;
use crate::parser::parse_expression::parse_expression_kind;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_argument_list(pair: Pair<'_>, context: &mut ParserContext) -> ArgumentList {
    let span = parse_span(&pair);
    let mut arguments: Vec<Argument> = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::argument => arguments.push(parse_argument(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    ArgumentList { arguments, span }
}

pub(super) fn parse_argument(pair: Pair<'_>, context: &mut ParserContext) -> Argument {
    let span = parse_span(&pair);
    let mut name: Option<Identifier> = None;
    let mut value: Option<ExpressionKind> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => name = Some(parse_identifier(&current)),
            Rule::named_argument => return parse_argument(current, context),
            Rule::expression => value = Some(parse_expression_kind(current, context)),
            Rule::empty_argument => context.insert_error(parse_span(&current), "ArgumentError: empty argument"),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Argument {
        span,
        name,
        value: Expression::new(value.unwrap_or(ExpressionKind::NullLiteral(NullLiteral::default()))),
    }
}
