use std::cell::RefCell;
use crate::ast::expression::{Expression, ExpressionKind};
use crate::ast::r#enum::{Enum, EnumMember};
use crate::{parse_append, parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_keyword, parse_insert_punctuation, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_argument_list_declaration::parse_argument_list_declaration;
use crate::parser::parse_arith_expr::parse_arith_expr;
use crate::parser::parse_code_comment::parse_code_comment;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_literals::{parse_numeric_literal, parse_string_literal};
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_enum_declaration(pair: Pair<'_>, context: &ParserContext) -> Enum {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut comment = None;
    let mut decorators = vec![];
    let mut interface = false;
    let mut option = false;
    let mut identifier = 0;
    let mut members = vec![];
    let mut inside_block = false;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::ENUM_KEYWORD => parse_insert_keyword!(context, current, children, "enum"),
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::BLOCK_OPEN => {
                parse_insert_punctuation!(context, current, children, "{");
                inside_block = true;
            },
            Rule::BLOCK_CLOSE => parse_insert_punctuation!(context, current, children, "}"),
            Rule::INTERFACE_KEYWORD => {
                parse_insert_keyword!(context, current, children, "interface");
                interface = true;
            },
            Rule::OPTION_KEYWORD => {
                parse_insert_keyword!(context, current, children, "option");
                option = true;
            },
            Rule::triple_comment_block => if !inside_block {
                parse_set_optional!(parse_doc_comment(current, context), children, comment)
            } else {
                context.insert_unattached_doc_comment(parse_span(&current));
                parse_append!(parse_doc_comment(current, context), children);
            },
            Rule::double_comment_block => parse_append!(parse_code_comment(current, context), children),
            Rule::decorator => parse_insert!(parse_decorator(current, context), children, decorators),
            Rule::empty_decorator => (),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::enum_member_declaration => parse_insert!(parse_enum_member(current, context, interface, option), children, members),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    Enum {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        interface,
        option,
        comment,
        decorators,
        identifier,
        members,
    }
}

fn parse_enum_member(pair: Pair<'_>, context: &ParserContext, interface: bool, _option: bool) -> EnumMember {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut comment = None;
    let mut decorators = vec![];
    let mut identifier = 0;
    let mut expression: Option<usize> = None;
    let mut argument_list_declaration: Option<usize> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON => parse_insert_punctuation!(context, current, children, ":"),
            Rule::ASSIGN => parse_insert_punctuation!(context, current, children, "="),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::decorator => parse_insert!(parse_decorator(current, context), children, decorators),
            Rule::empty_decorator => (),
            Rule::triple_comment_block => parse_set_optional!(parse_doc_comment(current, context), children, comment),
            Rule::enum_member_expression => parse_set_optional!(parse_enum_member_expression(current, context), children, expression),
            Rule::argument_list_declaration => {
                if !interface {
                    context.insert_error(parse_span(&current), "non interface enum cannot have argument list")
                }
                parse_set_optional!(parse_argument_list_declaration(current, context), children, argument_list_declaration);
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    EnumMember {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        comment,
        decorators,
        identifier,
        expression,
        argument_list_declaration,
        resolved: RefCell::new(None),
    }
}

fn parse_enum_member_expression(pair: Pair<'_>, context: &ParserContext) -> Expression {
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::arith_expr => return Expression::new(ExpressionKind::ArithExpr(parse_arith_expr(current, context))),
            Rule::string_literal => return Expression::new(ExpressionKind::StringLiteral(parse_string_literal(&current, context))),
            Rule::numeric_literal => return Expression::new(ExpressionKind::NumericLiteral(parse_numeric_literal(&current, context))),
            _ => context.insert_error(parse_span(&current), "invalid enum member expression"),
        }
    }
    unreachable!()
}