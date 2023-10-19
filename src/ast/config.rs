use crate::ast::availability::Availability;
use crate::ast::config_item::ConfigItem;
use crate::ast::config_keyword::ConfigKeyword;
use crate::ast::expr::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::info_provider::InfoProvider;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::span::Span;
use crate::search::search_availability::search_availability;

#[derive(Debug)]
pub struct Config {
    pub span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) keyword: ConfigKeyword,
    pub identifier: Option<Identifier>,
    pub items: Vec<ConfigItem>,
    pub define_availability: Availability,
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

    pub fn get_item(&self, name: impl AsRef<str>) -> Option<&Expression> {
        self.items.iter().find(|item| item.identifier.name() == name.as_ref()).map(|item| &item.expression)
    }
}

impl InfoProvider for Config {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self, schema: &Schema, source: &Source) -> Availability {
        search_availability(schema, source, &self.namespace_str_path())
    }
}