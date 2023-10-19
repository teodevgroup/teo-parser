use crate::ast::availability::Availability;
use crate::ast::expr::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct ConfigItem {
    pub span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub identifier: Identifier,
    pub expression: Expression,
    pub define_availability: Availability,
}
