use crate::ast::expr::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct ConfigItem {
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) identifier: Identifier,
    pub(crate) expression: Expression,
    pub(crate) span: Span,
}
