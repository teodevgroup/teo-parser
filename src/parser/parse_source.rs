use crate::ast::identifier_path::IdentifierPath;
use crate::ast::source::{Source, SourceReferences, SourceType};
use crate::parser::parse_identifier::parse_identifier;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use super::pest_parser::{Pair, Rule};

pub(super) fn parse_source(
    content: &str, path: impl Into<String>, builtin: bool, context: &mut ParserContext,
) -> Source {
    let path = path.into();
    let id = context.start_next_source(path.clone());
    let mut references = SourceReferences::new();
    Source::new(
        id,
        if builtin { SourceType::Builtin } else { SourceType::Normal },
        path,
        references
    )
}