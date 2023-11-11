use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::config_item::ConfigItem;
use crate::ast::config_keyword::ConfigKeyword;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;

#[derive(Debug)]
pub struct Config {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub keyword: ConfigKeyword,
    pub identifier: Option<Identifier>,
    pub items: Vec<ConfigItem>,
    pub unattached_identifiers: Vec<Identifier>,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
}

impl Config {

    pub fn name_span(&self) -> Span {
        if let Some(identifier) = &self.identifier {
            identifier.span
        } else {
            self.keyword.span
        }
    }

    pub fn get_item(&self, name: impl AsRef<str>) -> Option<&Expression> {
        self.items.iter().find(|item| item.identifier.name() == name.as_ref() && item.is_available()).map(|item| &item.expression)
    }
}

impl Identifiable for Config {

    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for Config {

    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }

    fn name(&self) -> &str {
        if let Some(identifier) = &self.identifier {
            identifier.name()
        } else {
            self.keyword.name()
        }
    }
}

impl HasAvailability for Config {

    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        self.actual_availability.borrow().clone()
    }
}

impl InfoProvider for Config {

    fn namespace_skip(&self) -> usize {
        1
    }
}