use std::cell::RefCell;
use crate::ast::data_set::{DataSet, DataSetGroup, DataSetRecord};
use crate::{parse_append, parse_container_node_variables, parse_container_node_variables_cleanup, parse_insert, parse_insert_keyword, parse_insert_punctuation, parse_set, parse_set_identifier_and_string_path, parse_set_optional};
use crate::parser::parse_code_comment::parse_code_comment;
use crate::parser::parse_doc_comment::parse_doc_comment;
use crate::parser::parse_identifier_path::parse_identifier_path;
use crate::parser::parse_literals::parse_dictionary_literal;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};
use crate::traits::identifiable::Identifiable;

pub(super) fn parse_data_set_declaration(pair: Pair<'_>, context: &ParserContext) -> DataSet {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut identifier = 0;
    let mut auto_seed = false;
    let mut notrack = false;
    let mut groups = vec![];
    let mut inside_block = false;
    let mut comment = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::DATASET_KEYWORD => parse_insert_keyword!(context, current, children, "dataset"),
            Rule::BLOCK_CLOSE => parse_insert_punctuation!(context, current, children, "}"),
            Rule::BLOCK_OPEN => {
                parse_insert_punctuation!(context, current, children, "{");
                inside_block = true;
            },
            Rule::AUTOSEED_KEYWORD => auto_seed = true,
            Rule::NOTRACK_KEYWORD => notrack = true,
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::dataset_group_declaration => parse_insert!(parse_data_set_group(current, context), children, groups),
            Rule::triple_comment_block => if !inside_block {
                parse_set_optional!(parse_doc_comment(current, context), children, comment)
            } else {
                context.insert_unattached_doc_comment(parse_span(&current));
                parse_append!(parse_doc_comment(current, context), children);
            },
            Rule::double_comment_block => parse_append!(parse_code_comment(current, context), children),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    DataSet {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        identifier,
        auto_seed,
        notrack,
        groups,
        comment,
    }
}

fn parse_data_set_group(pair: Pair<'_>, context: &ParserContext) -> DataSetGroup {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let mut identifier_path: usize = 0;
    let mut records = vec![];
    let inside_block = false;
    let mut comment = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::GROUP_KEYWORD => parse_insert_keyword!(context, current, children, "group"),
            Rule::BLOCK_OPEN => parse_insert_punctuation!(context, current, children, "{"),
            Rule::BLOCK_CLOSE => parse_insert_punctuation!(context, current, children, "}"),
            Rule::identifier_path => {
                let node = parse_identifier_path(current, context);
                identifier_path = node.id();
                string_path = context.next_parent_string_path(node.names().join("."));
                children.insert(node.id(), node.into());
            },
            Rule::dataset_group_record_declaration => parse_insert!(parse_data_set_group_record(current, context), children, records),
            Rule::triple_comment_block => if !inside_block {
                parse_set_optional!(parse_doc_comment(current, context), children, comment)
            } else {
                context.insert_unattached_doc_comment(parse_span(&current));
                parse_append!(parse_doc_comment(current, context), children);
            },
            Rule::double_comment_block => parse_append!(parse_code_comment(current, context), children),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    DataSetGroup {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        identifier_path,
        records,
        comment,
        resolved: RefCell::new(None),
    }
}

fn parse_data_set_group_record(pair: Pair<'_>, context: &ParserContext) -> DataSetRecord {
    let (
        span,
        path,
        mut string_path,
        mut children,
        define_availability,
        actual_availability
    ) = parse_container_node_variables!(pair, context, named, availability);
    let inside_block = false;
    let mut identifier = 0;
    let mut dictionary = 0;
    let mut comment = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::RECORD_KEYWORD => parse_insert_keyword!(context, current, children, "record"),
            Rule::identifier => parse_set_identifier_and_string_path!(context, current, children, identifier, string_path),
            Rule::dictionary_literal => parse_set!(parse_dictionary_literal(current, context, false), children, dictionary),
            Rule::triple_comment_block => if !inside_block {
                parse_set_optional!(parse_doc_comment(current, context), children, comment)
            } else {
                context.insert_unattached_doc_comment(parse_span(&current));
                parse_append!(parse_doc_comment(current, context), children);
            },
            Rule::double_comment_block => parse_append!(parse_code_comment(current, context), children),
            _ => (),
        }
    }
    parse_container_node_variables_cleanup!(context, named);
    DataSetRecord {
        span,
        path,
        string_path,
        children,
        define_availability,
        actual_availability,
        identifier,
        dictionary,
        comment,
        resolved: RefCell::new(None),
    }
}