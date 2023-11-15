use crate::ast::config::Config;
use crate::ast::config_item::ConfigItem;
use crate::ast::keyword::Keyword;
use crate::{parse_append, parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_punctuation, parse_node_variables, parse_set, parse_set_identifier_and_string_path};
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_config_block(pair: Pair<'_>, context: &mut ParserContext) -> Config {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut keyword: usize = 0;
    let mut identifier: Option<usize> = None;
    let mut items: Vec<usize> = vec![];
    let mut inside_block = false;
    let mut unattached_identifiers = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BLOCK_OPEN => {
                parse_insert_punctuation!(context, current, children, "{");
                string_path = context.next_parent_string_path(if let Some(identifier) = identifier { children.get(&identifier).unwrap().as_identifier().unwrap().name() } else { children.get(&keyword).unwrap().as_keyword().unwrap().name() });
                inside_block = true;
            },
            Rule::BLOCK_CLOSE => parse_insert_punctuation!(context, current, children, "}"),
            Rule::config_keywords => parse_set!(parse_config_keyword(current, context), children, keyword),
            Rule::identifier => if inside_block {
                unattached_identifiers.push(parse_identifier(&current, context));
            } else {
                parse_set!(parse_identifier(&current, context), children, identifier);
            },
            Rule::config_item => parse_insert!(parse_config_item(current, context), children, items),
            Rule::comment_block => parse_append!(parse_code_comment(current, context), children),
            Rule::availability_start => parse_append!(parse_availability_flag(current, context), children),
            Rule::availability_end => parse_append!(parse_availability_end(current, context), chilren),
            Rule::BLOCK_LEVEL_CATCH_ALL => context.insert_unparsed(parse_span(&current)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    Config {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        keyword,
        identifier,
        items,
        unattached_identifiers,
    }
}

fn parse_config_keyword(pair: Pair<'_>, context: &mut ParserContext) -> Keyword {
    let (span, path) = parse_node_variables!(pair, context);
    Keyword { span, path, name: pair.as_str().to_owned() }
}

fn parse_config_item(pair: Pair<'_>, context: &mut ParserContext) -> ConfigItem {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut identifier = 0;
    let mut expression= 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::expression => parse_set!(parse_expression(current, context), children, expression),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context);
    ConfigItem {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        identifier,
        expression,
    }
}