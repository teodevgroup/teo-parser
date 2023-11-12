use crate::ast::literals::StringLiteral;
use crate::ast::span::Span;
use crate::{declare_node, impl_node_defaults};

declare_node!(Import,
    pub source: StringLiteral,
    pub file_path: String,
);

impl_node_defaults!(Import);

impl Import {

    pub fn new(path: Vec<usize>, source: StringLiteral, file_path: String, span: Span) -> Self {
        Self {
            path,
            source,
            file_path,
            span,
        }
    }
}
