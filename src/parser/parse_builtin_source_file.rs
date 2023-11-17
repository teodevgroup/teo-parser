use crate::ast::source::Source;
use crate::parser::parse_source::parse_source;
use crate::parser::parser_context::ParserContext;

pub(super) fn parse_builtin_source_file(content: &str, path: impl Into<String>, context: &ParserContext) -> Source {
    parse_source(content, path, true, context)
}