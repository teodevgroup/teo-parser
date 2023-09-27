use std::cell::RefCell;
use crate::ast::data_set::{DataSet, DataSetGroup, DataSetGroupResolved, DataSetRecord};
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_data_set(pair: Pair<'_>, context: &mut ParserContext) -> DataSet {
    let span = parse_span(&pair);
    let mut identifier: Option<Identifier> = None;
    let mut auto_seed = false;
    let mut notrack = false;
    let mut groups = vec![];
    let parent_path = context.current_string_path();
    let path = context.next_parent_path();
    let mut string_path = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BLOCK_CLOSE | Rule::EMPTY_LINES => (),
            Rule::BLOCK_OPEN => string_path = Some(context.next_string_path(identifier.as_ref().unwrap().name())),
            Rule::AUTOSEED_KEYWORD => auto_seed = true,
            Rule::NOTRACK_KEYWORD => notrack = true,
            Rule::identifier => identifier = Some(parse_identifier(&current)),
            Rule::dataset_group_declaration => groups.push(parse_data_set_group(current, context)),
            Rule::comment_block => (),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    context.pop_string_path();
    DataSet {
        span,
        path,
        string_path: string_path.unwrap(),
        parent_path,
        identifier: identifier.unwrap(),
        auto_seed,
        notrack,
        groups,
    }
}

fn parse_data_set_group(pair: Pair<'_>, context: &mut ParserContext) -> DataSetGroup {
    let span = parse_span(&pair);
    let mut identifier_path: Option<IdentifierPath> = None;
    let mut records = vec![];
    let path = context.next_parent_path();
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::BLOCK_CLOSE | Rule::EMPTY_LINES => (),
            Rule::BLOCK_OPEN => (),
            Rule::identifier_path => identifier_path = Some(parse_identifier_path(current, context)),
            Rule::dataset_group_record_declaration => records.push(parse_data_set_group_record(current, context)),
            Rule::comment_block => (),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    context.pop_parent_id();
    DataSetGroup {
        span,
        path,
        identifier_path: identifier_path.unwrap(),
        records,
        resolved: RefCell::new(None),
    }
}

fn parse_data_set_group_record(pair: Pair<'_>, context: &mut ParserContext) -> DataSetRecord {

}