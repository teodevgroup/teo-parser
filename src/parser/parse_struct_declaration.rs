use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::struct_declaration::StructDeclaration;
use crate::parser::parse_comment::parse_comment;
use crate::parser::parse_function_declaration::parse_function_declaration;
use crate::parser::parse_generics::{parse_generics_constraint, parse_generics_declaration};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_struct_declaration(pair: Pair<'_>, context: &mut ParserContext) -> StructDeclaration {
    let span = parse_span(&pair);
    let path = context.next_parent_path();
    let mut string_path = None;
    let mut comment = None;
    let mut identifier = None;
    let mut generics_declaration = None;
    let mut generics_constraint = None;
    let mut function_declarations = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::COLON | Rule::BLOCK_OPEN | Rule::BLOCK_CLOSE | Rule::WHITESPACE | Rule::EMPTY_LINES | Rule::STRUCT_KEYWORD => (),
            Rule::triple_comment_block => comment = Some(parse_comment(current, context)),
            Rule::identifier => {
                identifier = Some(parse_identifier(&current));
                string_path = Some(context.next_parent_string_path(identifier.as_ref().unwrap().name()));
            },
            Rule::generics_declaration => generics_declaration = Some(parse_generics_declaration(current, context)),
            Rule::generics_constraint => generics_constraint = Some(parse_generics_constraint(current, context)),
            Rule::function_declaration => function_declarations.push(parse_function_declaration(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    context.pop_string_path();
    StructDeclaration {
        span,
        path,
        string_path: string_path.unwrap(),
        define_availability: context.current_availability_flag(),
        actual_availability: RefCell::new(Availability::none()),
        comment,
        identifier: identifier.unwrap(),
        generics_declaration,
        generics_constraint,
        function_declarations,
    }
}
