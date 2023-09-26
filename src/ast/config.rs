use crate::ast::config_item::ConfigItem;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Config {
    pub(crate) path: Vec<usize>,
    pub(crate) identifier: Option<Identifier>,
    pub(crate) items: Vec<ConfigItem>,
    pub(crate) span: Span,
}

impl Config {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }
}