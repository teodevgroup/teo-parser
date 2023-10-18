use crate::ast::config_item::ConfigItem;
use crate::ast::config_keyword::ConfigKeyword;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Config {
    pub span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) keyword: ConfigKeyword,
    pub identifier: Option<Identifier>,
    pub items: Vec<ConfigItem>,
}

impl Config {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn name(&self) -> &str {
        if let Some(identifier) = &self.identifier {
            identifier.name()
        } else {
            self.keyword.name()
        }
    }

    pub fn name_span(&self) -> Span {
        if let Some(identifier) = &self.identifier {
            identifier.span
        } else {
            self.keyword.span
        }
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }
}