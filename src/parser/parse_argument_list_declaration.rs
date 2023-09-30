use crate::ast::argument_declaration::{ArgumentDeclaration, ArgumentListDeclaration};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parse_type_expression::parse_type_expression;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_argument_list_declaration(pair: Pair<'_>, context: &mut ParserContext) -> ArgumentListDeclaration {
    let span = parse_span(&pair);
    let mut argument_declarations = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::argument_declaration => argument_declarations.push(parse_argument_declaration(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    ArgumentListDeclaration {
        span,
        argument_declarations,
    }
}

fn parse_argument_declaration(pair: Pair<'_>, context: &mut ParserContext) -> ArgumentDeclaration {
    let span = parse_span(&pair);
    let mut name = None;
    let mut name_optional = false;
    let mut type_expr = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => name = Some(parse_identifier(&current)),
            Rule::OPTIONAL => name_optional = true,
            Rule::type_expression => type_expr = Some(parse_type_expression(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    ArgumentDeclaration {
        span,
        name: name.unwrap(),
        name_optional,
        type_expr: type_expr.unwrap(),
    }
}