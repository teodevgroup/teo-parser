use crate::ast::doc_comment::DocComment;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_doc_comment(pair: Pair<'_>, context: &mut ParserContext) -> DocComment {
    let span = parse_span(&pair);
    let path = context.next_path();
    let mut name = None;
    let mut desc = "".to_owned();
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::triple_comment => {
                let (token, doc) = parse_comment_line(current, context);
                if let Some(token) = token {
                    if &token == "@name" {
                        name = Some(doc);
                    } else if &token == "@description" {
                        desc = append(desc, doc)
                    }
                } else {
                    desc = append(desc, doc)
                }
            },
            Rule::double_comment_block => {},
            Rule::double_comment => {},
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    DocComment {
        span,
        path,
        name,
        desc: if desc.is_empty() { None } else { Some(desc) },
    }
}

fn parse_comment_line(pair: Pair<'_>, context: &mut ParserContext) -> (Option<String>, String) {
    let mut token = None;
    let mut content = "".to_owned();
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::comment_token => token = Some(current.as_str().to_string()),
            Rule::doc_content => content = current.as_str().to_string(),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    (token, content)
}

fn append(desc: String, doc: String) -> String {
    if desc.is_empty() {
        doc.trim().to_owned()
    } else {
        desc + " " + doc.trim()
    }
}