use maplit::btreemap;
use pest::Parser;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::source::{Source, SourceReferences, SourceType};
use crate::ast::top::Top;
use crate::parser::parse_config_block::parse_config_block;
use crate::parser::parse_constant_statement::parse_constant_statement;
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_import_statement::parse_import_statement;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::SchemaParser;
use super::pest_parser::{Pair, Rule};

pub(super) fn parse_source(
    content: &str, path: impl Into<String>, builtin: bool, context: &mut ParserContext,
) -> Source {
    let path = path.into();
    let id = context.start_next_source(path.clone());
    let mut tops = btreemap!{};
    let mut references = SourceReferences::new();
    let mut pairs = match SchemaParser::parse(Rule::schema, &content) {
        Ok(pairs) => pairs,
        Err(err) => panic!("{}", err)
    };
    let pairs = pairs.next().unwrap();
    let mut pairs = pairs.into_inner().peekable();
    while let Some(current) = pairs.next() {
        match current.as_rule() {
            Rule::import_statement => { // import { a, b } from './some.schema'
                let import = parse_import_statement(current, path.as_ref(), context);
                references.imports.insert(import.id());
                tops.insert(import.id(), Top::Import(import));
            },
            Rule::constant_statement => { // let a = 5
                let constant = parse_constant_statement(current, context);
                references.constants.insert(constant.id());
                tops.insert(constant.id(), Top::Constant(constant));
            },
            Rule::config_block => { //
                let config = parse_config_block(current, context);
                references.configs.insert(config.id());
                tops.insert(config.id(), Top::Config(config));
            }
            _ => (),
        }
    }
    Source::new(
        id,
        if builtin { SourceType::Builtin } else { SourceType::Normal },
        path,
        tops,
        references
    )
}