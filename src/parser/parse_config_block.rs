use std::cell::RefCell;
use crate::ast::config::Config;
use crate::ast::config_item::ConfigItem;
use crate::ast::config_keyword::ConfigKeyword;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_expression::parse_expression_kind;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_config_block(pair: Pair<'_>, context: &mut ParserContext) -> Config {
    let span = parse_span(&pair);
    let mut keyword: Option<ConfigKeyword> = None;
    let mut identifier: Option<Identifier> = None;
    let mut items: Vec<ConfigItem> = vec![];
    let mut inside_block = false;
    let mut unattached_identifiers = vec![];
    let path = context.next_parent_path();
    let mut string_path = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BLOCK_OPEN => {
                string_path = Some(context.next_parent_string_path(if identifier.is_some() { identifier.as_ref().unwrap().name() } else { keyword.as_ref().unwrap().name() }));
                inside_block = true;
            },
            Rule::BLOCK_CLOSE | Rule::EMPTY_LINES => (),
            Rule::config_keywords => keyword = Some(parse_config_keyword(current)),
            Rule::identifier => if inside_block {
                unattached_identifiers.push(parse_identifier(&current));
            } else {
                identifier = Some(parse_identifier(&current));
            },
            Rule::config_item => items.push(parse_config_item(current, context)),
            Rule::comment_block => (),
            Rule::availability_start => parse_availability_flag(current, context),
            Rule::availability_end => parse_availability_end(current, context),
            Rule::BLOCK_LEVEL_CATCH_ALL => context.insert_unparsed(parse_span(&current)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    context.pop_string_path();
    Config {
        span,
        path,
        string_path: string_path.unwrap(),
        keyword: keyword.unwrap(),
        identifier,
        unattached_identifiers,
        items,
        define_availability: context.current_availability_flag(),
        resolved: RefCell::new(None),
    }
}

fn parse_config_keyword(pair: Pair<'_>) -> ConfigKeyword {
    ConfigKeyword { span: parse_span(&pair), name: pair.as_str().to_owned() }
}

fn parse_config_item(pair: Pair<'_>, context: &mut ParserContext) -> ConfigItem {
    let span = parse_span(&pair);
    let mut identifier: Option<Identifier> = None;
    let mut expression: Option<Expression> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::expression => expression = Some(Expression::new(parse_expression_kind(current, context))),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    ConfigItem {
        span,
        path: context.next_path(),
        string_path: context.next_string_path(identifier.as_ref().unwrap().name()),
        define_availability: context.current_availability_flag(),
        identifier: identifier.unwrap(),
        expression: expression.unwrap(),
        resolved: RefCell::new(None),
    }
}