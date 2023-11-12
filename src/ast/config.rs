use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::config_item::ConfigItem;
use crate::ast::config_keyword::ConfigKeyword;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::{declare_container_node, impl_container_node_defaults, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::node_trait::NodeTrait;

declare_container_node!(Config, named, availability,
    pub keyword: ConfigKeyword,
    pub identifier: Option<usize>,
    pub items: Vec<usize>,
    pub unattached_identifiers: Vec<Identifier>
);

node_children_iter!(Config, ConfigItem, ItemsIter, items, as_config_item);

impl_container_node_defaults!(Config, availability);

impl Config {

    node_optional_child_fn!(identifier, Identifier, as_identifier);

    node_children_iter_fn!(items, ItemsIter);

    pub fn name_span(&self) -> Span {
        if let Some(identifier) = self.identifier() {
            identifier.span()
        } else {
            self.keyword.span
        }
    }

    pub fn get_item(&self, name: impl AsRef<str>) -> Option<&Expression> {
        self.items().find(|item| item.identifier.name() == name.as_ref() && item.is_available()).map(|item| &item.expression)
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

impl InfoProvider for Config {

    fn namespace_skip(&self) -> usize {
        1
    }
}