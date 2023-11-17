use crate::ast::code_comment::CodeComment;
use crate::ast::doc_comment::DocComment;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_code_comment(pair: Pair<'_>, context: &ParserContext) -> CodeComment {
    let span = parse_span(&pair);
    let path = context.next_path();
    let mut lines = vec![];
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::double_comment => {
                lines.push(parse_comment_line(current, context));
            },
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    CodeComment {
        span,
        path,
        lines,
    }
}

fn parse_comment_line(pair: Pair<'_>, context: &ParserContext) -> String {
    let mut content = "".to_owned();
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::doc_content => content = current.as_str().to_string(),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    content
}
