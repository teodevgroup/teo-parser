use crate::ast::config_item::ConfigItem;
use crate::ast::config_keyword::ConfigKeyword;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Config {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) keyword: ConfigKeyword,
    pub(crate) identifier: Option<Identifier>,
    pub(crate) items: Vec<ConfigItem>,
}

impl Config {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }
}