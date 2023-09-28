use crate::ast::expr::ExpressionKind;
use crate::ast::literals::NullLiteral;
use crate::ast::unit::Unit;
use crate::parser::parse_argument::parse_argument_list;
use crate::parser::parse_arith_expr::parse_arith_expr;
use crate::parser::parse_group::parse_group;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_literals::{parse_array_literal, parse_bool_literal, parse_dictionary_literal, parse_enum_variant_literal, parse_null_literal, parse_numeric_literal, parse_range_literal, parse_regexp_literal, parse_string_literal, parse_tuple_literal};
use crate::parser::parse_pipeline::parse_pipeline;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_subscript::parse_subscript;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_expression_kind(pair: Pair<'_>, context: &mut ParserContext) -> ExpressionKind {
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::arith_expr => return ExpressionKind::ArithExpr(parse_arith_expr(current, context)),
            Rule::unit => return ExpressionKind::Unit(parse_unit(current, context)),
            Rule::pipeline => return ExpressionKind::Pipeline(parse_pipeline(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    ExpressionKind::NullLiteral(NullLiteral::default())
}

pub(super) fn parse_unit(pair: Pair<'_>, context: &mut ParserContext) -> Unit {
    let span = parse_span(&pair);
    let mut expressions = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::group => expressions.push(ExpressionKind::Group(parse_group(current, context))),
            Rule::null_literal => expressions.push(ExpressionKind::NullLiteral(parse_null_literal(&current))),
            Rule::bool_literal => expressions.push(ExpressionKind::BoolLiteral(parse_bool_literal(&current))),
            Rule::numeric_literal => expressions.push(ExpressionKind::NumericLiteral(parse_numeric_literal(&current, context))),
            Rule::string_literal => expressions.push(ExpressionKind::StringLiteral(parse_string_literal(&current))),
            Rule::regexp_literal => expressions.push(ExpressionKind::RegExpLiteral(parse_regexp_literal(current, context))),
            Rule::enum_choice_literal => expressions.push(ExpressionKind::EnumVariantLiteral(parse_enum_variant_literal(current, context))),
            Rule::tuple_literal => expressions.push(ExpressionKind::TupleLiteral(parse_tuple_literal(current, context))),
            Rule::array_literal => expressions.push(ExpressionKind::ArrayLiteral(parse_array_literal(current, context))),
            Rule::dictionary_literal => expressions.push(ExpressionKind::DictionaryLiteral(parse_dictionary_literal(current, context))),
            Rule::range_literal => expressions.push(ExpressionKind::RangeLiteral(parse_range_literal(current, context))),
            Rule::identifier => expressions.push(ExpressionKind::Identifier(parse_identifier(&current))),
            Rule::subscript => expressions.push(ExpressionKind::Subscript(parse_subscript(current, context))),
            Rule::argument_list => expressions.push(ExpressionKind::ArgumentList(parse_argument_list(current, context))),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Unit { span, expressions }
}