use std::cell::RefCell;
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::literals::NullLiteral;
use crate::ast::unit::Unit;
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
            Rule::group => expressions.push(Expression { kind: ExpressionKind::Group(parse_group(current, context)), resolved: RefCell::new(None) }),
            Rule::null_literal => expressions.push(Expression { kind: ExpressionKind::NullLiteral(parse_null_literal(&current)), resolved: RefCell::new(None) }),
            Rule::bool_literal => expressions.push(Expression { kind: ExpressionKind::BoolLiteral(parse_bool_literal(&current)), resolved: RefCell::new(None) }),
            Rule::numeric_literal => expressions.push(Expression { kind: ExpressionKind::NumericLiteral(parse_numeric_literal(&current, context)), resolved: RefCell::new(None) }),
            Rule::string_literal => expressions.push(Expression { kind: ExpressionKind::StringLiteral(parse_string_literal(&current)), resolved: RefCell::new(None) }),
            Rule::regex_literal => expressions.push(Expression { kind: ExpressionKind::RegexLiteral(parse_regex_literal(current, context)), resolved: RefCell::new(None) }),
            Rule::enum_variant_literal => expressions.push(Expression { kind: ExpressionKind::EnumVariantLiteral(parse_enum_variant_literal(current, context)), resolved: RefCell::new(None) }),
            Rule::tuple_literal => expressions.push(Expression { kind: ExpressionKind::TupleLiteral(parse_tuple_literal(current, context)), resolved: RefCell::new(None) }),
            Rule::array_literal => expressions.push(Expression { kind: ExpressionKind::ArrayLiteral(parse_array_literal(current, context)), resolved: RefCell::new(None) }),
            Rule::dictionary_literal => expressions.push(Expression { kind: ExpressionKind::DictionaryLiteral(parse_dictionary_literal(current, context)), resolved: RefCell::new(None) }),
            Rule::identifier => expressions.push(Expression { kind: ExpressionKind::Identifier(parse_identifier(&current)), resolved: RefCell::new(None) }),
            Rule::subscript => expressions.push(Expression { kind: ExpressionKind::Subscript(parse_subscript(current, context)), resolved: RefCell::new(None) }),
            Rule::int_subscript => expressions.push(Expression { kind: ExpressionKind::IntSubscript(parse_int_subscript(current, context)), resolved: RefCell::new(None) }),
            Rule::argument_list => expressions.push(Expression { kind: ExpressionKind::ArgumentList(parse_argument_list(current, context)), resolved: RefCell::new(None) }),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Unit { span, expressions }
}