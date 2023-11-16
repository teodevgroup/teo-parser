use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::unit::Unit;
use crate::{parse_container_node_variables, parse_insert, parse_insert_punctuation};
use crate::parser::parse_argument::parse_argument_list;
use crate::parser::parse_arith_expr::parse_arith_expr;
use crate::parser::parse_group::parse_group;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_literals::{parse_array_literal, parse_bool_literal, parse_dictionary_literal, parse_enum_variant_literal, parse_null_literal, parse_numeric_literal, parse_regex_literal, parse_string_literal, parse_tuple_literal};
use crate::parser::parse_pipeline::parse_pipeline;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_subscript::{parse_int_subscript, parse_subscript};
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_expression(pair: Pair<'_>, context: &mut ParserContext) -> Expression {
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::arith_expr => return Expression::new(ExpressionKind::ArithExpr(parse_arith_expr(current, context))),
            Rule::unit => return Expression::new(ExpressionKind::Unit(parse_unit(current, context))),
            Rule::pipeline => return Expression::new(ExpressionKind::Pipeline(parse_pipeline(current, context))),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    unreachable!()
}

pub(super) fn parse_unit(pair: Pair<'_>, context: &mut ParserContext) -> Unit {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut expressions = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::DOT => parse_insert_punctuation!(context, current, children, "."),
            Rule::group => parse_insert!(Expression::new(ExpressionKind::Group(parse_group(current, context))), children, expressions),
            Rule::null_literal => parse_insert!(Expression::new(ExpressionKind::NullLiteral(parse_null_literal(&current, context))), children, expressions),
            Rule::bool_literal => parse_insert!(Expression::new(ExpressionKind::BoolLiteral(parse_bool_literal(&current, context))), children, expressions),
            Rule::numeric_literal => parse_insert!(Expression::new(ExpressionKind::NumericLiteral(parse_numeric_literal(&current, context))), children, expressions),
            Rule::string_literal => parse_insert!(Expression::new(ExpressionKind::StringLiteral(parse_string_literal(&current, context))), children, expressions),
            Rule::regex_literal => parse_insert!(Expression::new(ExpressionKind::RegexLiteral(parse_regex_literal(current, context))), children, expressions),
            Rule::enum_variant_literal => parse_insert!(Expression::new(ExpressionKind::EnumVariantLiteral(parse_enum_variant_literal(current, context))), children, expressions),
            Rule::tuple_literal => parse_insert!(Expression::new(ExpressionKind::TupleLiteral(parse_tuple_literal(current, context))), children, expressions),
            Rule::array_literal => parse_insert!(Expression::new(ExpressionKind::ArrayLiteral(parse_array_literal(current, context))), children, expressions),
            Rule::dictionary_literal => parse_insert!(Expression::new(ExpressionKind::DictionaryLiteral(parse_dictionary_literal(current, context))), children, expressions),
            Rule::identifier => parse_insert!(Expression::new(ExpressionKind::Identifier(parse_identifier(&current, context))), children, expressions),
            Rule::subscript => parse_insert!(Expression::new(ExpressionKind::Subscript(parse_subscript(current, context))), children, expressions),
            Rule::int_subscript => parse_insert!(Expression::new(ExpressionKind::IntSubscript(parse_int_subscript(current, context))), children, expressions),
            Rule::argument_list => parse_insert!(Expression::new(ExpressionKind::ArgumentList(parse_argument_list(current, context))), children, expressions),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Unit { span, children, path, expressions }
}