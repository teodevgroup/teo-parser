use std::cell::RefCell;
use std::collections::BTreeMap;
use maplit::btreemap;
use crate::ast::argument::Argument;
use crate::ast::argument_list::ArgumentList;
use crate::ast::node::Node;
use crate::ast::punctuations::Punctuation;
use crate::{insert_punctuation, parse_container_node_variables};
use crate::parser::parse_expression::parse_expression;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_argument_list(pair: Pair<'_>, context: &mut ParserContext) -> ArgumentList {
    parse_container_node_variables!();
    let mut arguments = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::argument => {
                let argument = parse_argument(current, context);
                arguments.push(argument.id());
                children.insert(argument.id(), Node::Argument(argument));
            },
            Rule::COMMA => insert_punctuation!(","),
            Rule::empty_argument => context.insert_error(parse_span(&current), "empty argument"),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    ArgumentList {
        span,
        path,
        children,
        arguments,
    }
}

pub(super) fn parse_argument(pair: Pair<'_>, context: &mut ParserContext) -> Argument {
    let span = parse_span(&pair);
    let mut children: BTreeMap<usize, Node> = btreemap! {};
    let path = context.next_parent_path();
    let mut name: Option<usize> = None;
    let mut value: usize = 0;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => {
                let identifier = parse_identifier(&current);
                name = Some(identifier.id());
                children.insert(identifier.id(), identifier.into());
            },
            Rule::expression => {
                let expression = parse_expression(current, context);
                value = expression.id();
                children.insert(expression.id(), expression.into());
            },
            Rule::COLON => insert_punctuation!(":"),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    Argument {
        span,
        children,
        path,
        name,
        value,
        resolved: RefCell::new(None),
    }
}
