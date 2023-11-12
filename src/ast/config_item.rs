use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn};
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;

declare_container_node!(ConfigItem, named, availability,
    pub identifier: usize,
    pub expression: usize,
);

impl_container_node_defaults!(ConfigItem, named, availability);

impl ConfigItem {

    node_child_fn!(identifier, Identifier);

    node_child_fn!(expression, Expression);
}

impl InfoProvider for ConfigItem {

    fn namespace_skip(&self) -> usize {
        2
    }
}