use crate::ast::identifier::Identifier;
use crate::ast::import::Import;
use crate::ast::literals::StringLiteral;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_literals::parse_string_literal;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::utils::path::import_path;

pub(super) fn parse_import_statement(pair: Pair<'_>, source_path: &str, context: &mut ParserContext) -> Import {
    let span = parse_span(&pair);
    let mut identifiers = vec![];
    let mut source: Option<StringLiteral> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::string_literal => source = Some(parse_string_literal(&current)),
            Rule::import_identifier_list => identifiers = parse_import_identifier_list(current, context),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    let file_path = import_path(source_path, source.as_ref().unwrap().value.as_str());
    if !(context.file_util.file_exists)(&file_path) {
        context.insert_error(source.as_ref().unwrap().span.clone(), "ImportError: file doesn't exist")
    }
    Import {
        path: context.next_path(),
        identifiers,
        source: source.unwrap(),
        span,
        file_path,
    }
}

fn parse_import_identifier_list(pair: Pair<'_>, context: &mut ParserContext) -> Vec<Identifier> {
    let mut identifiers = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier => identifiers.push(parse_identifier(&current)),
            Rule::TRAILING_COMMA | Rule::BLOCK_CLOSE => (),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    identifiers
}