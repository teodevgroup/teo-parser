use std::cell::RefCell;
use std::sync::atomic::AtomicBool;
use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::identifier::Identifier;
use crate::ast::r#enum::{Enum, EnumMember, EnumMemberExpression};
use crate::parser::parse_argument_list_declaration::parse_argument_list_declaration;
use crate::parser::parse_arith_expr::parse_arith_expr;
use crate::parser::parse_availability_end::parse_availability_end;
use crate::parser::parse_availability_flag::parse_availability_flag;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_decorator::parse_decorator;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_literals::{parse_numeric_literal, parse_string_literal};
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_enum_declaration(pair: Pair<'_>, context: &mut ParserContext) -> Enum {
    let span = parse_span(&pair);
    let mut comment = None;
    let mut decorators = vec![];
    let mut interface = false;
    let mut option = false;
    let mut identifier: Option<Identifier> = None;
    let mut members = vec![];
    let path = context.next_parent_path();
    let mut string_path = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::ENUM_KEYWORD | Rule::COLON | Rule::EMPTY_LINES | Rule::BLOCK_CLOSE => {},
            Rule::INTERFACE_KEYWORD => interface = true,
            Rule::OPTION_KEYWORD => option = true,
            Rule::BLOCK_OPEN => string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name())),
            Rule::comment_block | Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::decorator => decorators.push(parse_decorator(current, context)),
            Rule::empty_decorator => (),
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::enum_member_declaration => members.push(parse_enum_member(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_string_path();
    context.pop_parent_id();
    Enum {
        span,
        path,
        string_path: string_path.unwrap(),
        define_availability: context.current_availability_flag(),
        comment,
        decorators,
        interface,
        option,
        identifier: identifier.unwrap(),
        members,
        resolved: AtomicBool::new(false),
    }
}

fn parse_enum_member(pair: Pair<'_>, context: &mut ParserContext) -> EnumMember {
    let span = parse_span(&pair);
    let path = context.next_path();
    let mut string_path = None;
    let mut comment = None;
    let mut decorators = vec![];
    let mut identifier: Option<Identifier> = None;
    let mut expression: Option<EnumMemberExpression> = None;
    let mut argument_list_declaration: Option<ArgumentListDeclaration> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON | Rule::EMPTY_LINES => {},
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                string_path = Some(context.next_string_path(identifier.as_ref().unwrap().name()));
            },
            Rule::decorator => decorators.push(parse_decorator(current, context)),
            Rule::empty_decorator => (),
            Rule::comment_block | Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::enum_member_expression => expression = Some(parse_enum_member_expression(current, context)),
            Rule::argument_list_declaration => argument_list_declaration = Some(parse_argument_list_declaration(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    EnumMember {
        span,
        path,
        string_path: string_path.unwrap(),
        define_availability: context.current_availability_flag(),
        comment,
        decorators,
        identifier: identifier.unwrap(),
        expression,
        argument_list_declaration,
        resolved: RefCell::new(None),
    }
}

fn parse_enum_member_expression(pair: Pair<'_>, context: &mut ParserContext) -> EnumMemberExpression {
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::arith_expr => return EnumMemberExpression::ArithExpr(parse_arith_expr(current, context)),
            Rule::string_literal => return EnumMemberExpression::StringLiteral(parse_string_literal(&current)),
            Rule::numeric_literal => return EnumMemberExpression::NumericLiteral(parse_numeric_literal(&current, context)),
            Rule::availability_start => parse_availability_flag(current, context),
            Rule::availability_end => parse_availability_end(current, context),
            _ => panic!("unreachable 1"),
        }
    }
    panic!("unreachable 2")
}