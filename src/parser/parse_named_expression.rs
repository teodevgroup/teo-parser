use crate::ast::expression::ExpressionKind;
use crate::ast::named_expression::NamedExpression;
use crate::ast::punctuations::Punctuation;
use crate::{parse_container_node_variables, parse_container_node_variables_cleanup, parse_set};
use crate::parser::parse_bracket_expression::parse_bracket_expression;
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_literals::parse_string_literal;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::ast::expression::Expression;

pub(super) fn parse_named_expression(pair: Pair<'_>, context: &ParserContext) -> NamedExpression {
    let (
        span,
        path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, availability);
    let mut key = 0;
    let mut colon = None;
    let mut value = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::string_literal => parse_set!(Expression::new(ExpressionKind::StringLiteral(parse_string_literal(&current, context))), children, key),
            Rule::identifier => parse_set!(Expression::new(ExpressionKind::Identifier(parse_identifier(&current, context))), children, key),
            Rule::bracket_expression => parse_set!(Expression::new(ExpressionKind::BracketExpression(parse_bracket_expression(current, context))), children, key),
            Rule::expression => parse_set!(parse_expression(current, context), children, value),
            Rule::COLON => colon = Some(Punctuation::new(":", parse_span(&current), context.next_path())),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    NamedExpression {
        span,
        children,
        define_availability,
        path,
        key,
        value,
        actual_availability,
    }
}
