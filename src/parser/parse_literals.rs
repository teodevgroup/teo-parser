use std::cell::RefCell;
use std::str::FromStr;
use snailquote::unescape;
use regex::Regex;
use teo_teon::value::Value;
use crate::ast::argument_list::ArgumentList;
use crate::ast::expression::Expression;
use crate::ast::literals::{ArrayLiteral, BoolLiteral, DictionaryLiteral, EnumVariantLiteral, NullLiteral, NumericLiteral, RegexLiteral, StringLiteral, TupleLiteral};
use crate::{parse_container_node_variables, parse_insert, parse_node_variables, parse_set, parse_set_optional};
use crate::parser::parse_argument::parse_argument_list;
use crate::parser::parse_expression::{parse_expression};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_string_literal(pair: &Pair<'_>, context: &mut ParserContext) -> StringLiteral {
    let (span, path) = parse_node_variables!(pair, context);
    StringLiteral {
        span,
        path,
        display: pair.as_str().to_owned(),
        value: unescape(pair.as_str()).unwrap(),
    }
}

pub(super) fn parse_null_literal(pair: &Pair<'_>, context: &mut ParserContext) -> NullLiteral {
    let (span, path) = parse_node_variables!(pair, context);
    NullLiteral { span, path }
}

pub(super) fn parse_bool_literal(pair: &Pair<'_>, context: &mut ParserContext) -> BoolLiteral {
    let (span, path) = parse_node_variables!(pair, context);
    BoolLiteral { span, path, value: pair.as_str() == "true" }
}

pub(super) fn parse_regex_literal(pair: Pair<'_>, context: &mut ParserContext) -> RegexLiteral {
    let (span, path) = parse_node_variables!(pair, context);
    let mut display = pair.as_str().to_owned();
    let mut value = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::regex_content => match Regex::new(current.as_str()) {
                Ok(regex) => value = Some(regex),
                Err(_) => context.insert_error(span.clone(), "invalid regular expression"),
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    RegexLiteral {
        span,
        path,
        value: value.unwrap_or(Regex::new("").unwrap()),
        display,
    }
}

pub(super) fn parse_numeric_literal(pair: &Pair<'_>, _context: &mut ParserContext) -> NumericLiteral {
    let (span, path) = parse_node_variables!(pair, context);
    let str_value = pair.as_str();
    NumericLiteral {
        span, path,
        display: str_value.to_owned(),
        value: if str_value.contains(".") { // default to float64
            Value::Float(f64::from_str(&str_value).unwrap())
        } else if let Ok(i32v) = i32::from_str(str_value) {
            Value::Int(i32v)
        } else {
            Value::Int64(i64::from_str(str_value).unwrap())
        }
    }
}

pub(super) fn parse_enum_variant_literal(pair: Pair<'_>, context: &mut ParserContext) -> EnumVariantLiteral {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut argument_list: Option<usize> = None;
    let mut identifier = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => parse_set!(parse_identifier(&current), children, identifier),
            Rule::argument_list => parse_set_optional!(parse_argument_list(current, context), children, argument_list),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    EnumVariantLiteral {
        span,
        children,
        path,
        identifier,
        argument_list,
    }
}

pub(super) fn parse_array_literal(pair: Pair<'_>, context: &mut ParserContext) -> ArrayLiteral {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut expressions = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::expression => parse_insert!(parse_expression(current, context), children, expressions),
            Rule::comment_block => (),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    ArrayLiteral { expressions, span, children, path }
}

pub(super) fn parse_tuple_literal(pair: Pair<'_>, context: &mut ParserContext) -> TupleLiteral {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut expressions = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::expression => parse_insert!(parse_expression(current, context), children, expressions),
            Rule::comment_block => (),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    TupleLiteral { expressions, span, children, path }
}

pub(super) fn parse_dictionary_literal(pair: Pair<'_>, context: &mut ParserContext) -> DictionaryLiteral {
    let (
        span,
        path,
        mut children,
    ) = parse_container_node_variables!(pair, context);
    let mut expressions: Vec<(usize, usize)> = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::named_expression => {
                let (key, value) = parse_named_expression(current, context);
                expressions.push((key.id(), value.id()));
                children.insert(key.id(), key.into());
                children.insert(value.id(), value.into());
            },
            Rule::BLOCK_OPEN | Rule::BLOCK_CLOSE | Rule::comment_block => (),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    DictionaryLiteral { expressions, span, children, path }
}

fn parse_named_expression(pair: Pair<'_>, context: &mut ParserContext) -> (Expression, Expression) {
    let mut key = None;
    let mut value = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::expression => if key.is_none() {
                key = Some(parse_expression(current, context));
            } else {
                value = Some(parse_expression(current, context));
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    return (key.unwrap(), value.unwrap())
}
