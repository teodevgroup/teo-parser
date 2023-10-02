use std::borrow::Cow;
use std::fs;
use crate::ast::source::Source;
use crate::parser::parse_source::parse_source;
use crate::parser::parser_context::ParserContext;
use crate::utils;

pub(super) fn parse_source_file(path: impl AsRef<str>, base_path: &str, context: &mut ParserContext) -> Source {
    let path_str = path.as_ref();
    let abs_path = if utils::path::is_absolute(path_str) {
        Cow::Borrowed(path_str)
    } else {
        Cow::Owned(utils::path::join_path(base_path, path_str))
    };
    let content = match fs::read_to_string(abs_path) {
        Ok(content) => content,
        Err(err) => panic!("Cannot read schema file content at '{}': {}", abs_path, err)
    };
    parse_source(&content, abs_path.as_ref(), false, context)
}