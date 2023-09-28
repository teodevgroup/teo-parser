use crate::ast::pipeline::Pipeline;
use crate::ast::unit::Unit;
use crate::parser::parse_expression::parse_unit;
use crate::parser::parse_span::parse_span;
use crate::parser::parser_context::ParserContext;
use crate::parser::pest_parser::{Pair, Rule};

pub(super) fn parse_pipeline(pair: Pair<'_>, context: &mut ParserContext) -> Pipeline {
    let span = parse_span(&pair);
    let mut unit: Option<Unit> = None;
    for current in pair.into_inner() {
        match current.as_rule() {
            Rule::identifier_unit => unit = Some(parse_unit(current, context)),
            _ => context.insert_unparsed(parse_span(&current)),
        }
    }
    Pipeline {
        unit: Box::new(unit.unwrap()),
        span,
    }
}