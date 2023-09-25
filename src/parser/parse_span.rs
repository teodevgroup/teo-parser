use super::super::ast::span::Span;
use super::pest_parser::Pair;

pub(super) fn parse_span(pair: &Pair<'_>) -> Span {
    let start_line_col = pair.line_col();
    let pest_span = pair.as_span();
    let end_line_col = pest_span.end_pos().line_col();
    Span {
        start: pest_span.start(),
        end: pest_span.end(),
        start_position: start_line_col,
        end_position: end_line_col,
    }
}
