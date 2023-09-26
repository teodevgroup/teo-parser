use std::fs;
use std::path::Path;
use path_clean::PathClean;
use crate::ast::source::Source;
use crate::parser::parse_source::parse_source;
use crate::parser::parser_context::ParserContext;

pub(super) fn parse_source_file(path: impl AsRef<str>, base_path: &Path, context: &mut ParserContext) -> Source {
    let path_str = path.as_ref();
    let rel_path = Path::new(path_str);
    let abs_path = base_path.join(rel_path).clean();
    let content = match fs::read_to_string(&abs_path) {
        Ok(content) => content,
        Err(err) => panic!("Cannot read schema file content at '{}': {}", abs_path.as_os_str().to_str().unwrap(), err)
    };
    parse_source(&content, path.as_ref().to_string(), false, context)
}