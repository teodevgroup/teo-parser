use std::str::FromStr;
use snailquote::unescape;
use regex::Regex;
use teo_teon::value::Value;
use crate::ast::literals::{BoolLiteral, NullLiteral, NumericLiteral, RegExpLiteral, StringLiteral};
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_string_literal(pair: &Pair<'_>) -> StringLiteral {
    StringLiteral {
        value: unescape(pair.as_str()).unwrap(),
        span: parse_span(&pair),
    }
}

pub(super) fn parse_null_literal(pair: &Pair<'_>) -> NullLiteral {
    NullLiteral { span: parse_span(&pair) }
}

pub(super) fn parse_bool_literal(pair: &Pair<'_>) -> BoolLiteral {
    BoolLiteral {
        span: parse_span(&pair),
        value: pair.as_str() == "true",
    }
}

pub(super) fn parse_regexp_literal(pair: &Pair<'_>, context: &mut ParserContext) -> RegExpLiteral {
    let span = parse_span(&pair);
    let mut value = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::regexp_content => match Regex::new(current.as_str()) {
                Ok(regexp) => value = Some(regexp),
                Err(err) => context.insert_error(span.clone(), "RegExpError: invalid regular expression"),
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    RegExpLiteral {
        value: value.unwrap_or(Regex::new("").unwrap()),
        span,
    }
}

pub(super) fn parse_numeric_literal(pair: &Pair<'_>, _context: &mut ParserContext) -> NumericLiteral {
    let str_value = pair.as_str();
    NumericLiteral {
        span: parse_span(&pair),
        value: if str_value.contains(".") { // default to float64
            Value::F64(f64::from_str(&str_value).unwrap())
        } else if let Ok(i32v) = i32::from_str(str_value) {
            Value::I32(i32v)
        } else {
            Value::I64(i64::from_str(str_value).unwrap())
        }
    }
}