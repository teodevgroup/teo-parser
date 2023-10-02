use serde_json::to_string;
use crate::diagnostics::diagnostics::{Diagnostics, DiagnosticsError, DiagnosticsLog, DiagnosticsWarning};
use serde::Serialize;
use crate::ast::span::Span;

#[derive(Debug, Serialize)]
struct DiagnosticsJsonItemSpan {
    start: usize,
    end: usize,
    start_position: (usize, usize),
    end_position: (usize, usize),
}

impl From<&Span> for DiagnosticsJsonItemSpan {

    fn from(value: &Span) -> Self {
        DiagnosticsJsonItemSpan {
            start: value.start,
            end: value.end,
            start_position: value.start_position,
            end_position: value.end_position,
        }
    }
}

#[derive(Debug, Serialize)]
struct DiagnosticsJsonItem {
    r#type: &'static str,
    source: String,
    message: String,
    span: DiagnosticsJsonItemSpan,
}

impl From<&DiagnosticsError> for DiagnosticsJsonItem {

    fn from(value: &DiagnosticsError) -> Self {
        DiagnosticsJsonItem {
            r#type: "error",
            source: value.source_path().to_string(),
            message: value.message().to_string(),
            span: DiagnosticsJsonItemSpan::from(value.span()),
        }
    }
}

impl From<&DiagnosticsWarning> for DiagnosticsJsonItem {

    fn from(value: &DiagnosticsWarning) -> Self {
        DiagnosticsJsonItem {
            r#type: "warning",
            source: value.source_path().to_string(),
            message: value.message().to_string(),
            span: DiagnosticsJsonItemSpan::from(value.span()),
        }
    }
}

pub(crate) fn format_to_json(diagnostics: &Diagnostics, include_warnings: bool) -> String {
    let mut result = vec![];
    for error in diagnostics.errors() {
        result.push(error.into());
    }
    if include_warnings {
        for warning in diagnostics.warnings() {
            result.push(warning.into());
        }
    }
    to_string(&result).unwrap()
}