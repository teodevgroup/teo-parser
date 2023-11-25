use crate::ast::keyword::Keyword;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::{declare_container_node, impl_container_node_defaults, node_optional_child_fn, node_child_fn};
use crate::ast::literals::DictionaryLiteral;
use crate::format::Writer;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(Config, named, availability,
    pub keyword: usize,
    pub identifier: Option<usize>,
    pub dictionary_literal: usize,
    pub unattached_identifiers: Vec<Identifier>
);

impl_container_node_defaults!(Config, availability);

impl Config {

    node_child_fn!(keyword, Keyword);

    node_optional_child_fn!(identifier, Identifier);

    node_child_fn!(dictionary_literal, DictionaryLiteral);

    pub fn name_span(&self) -> Span {
        if let Some(identifier) = self.identifier() {
            identifier.span()
        } else {
            self.keyword().span
        }
    }

    pub fn get_item(&self, name: impl AsRef<str>) -> Option<&Expression> {
        self.dictionary_literal().expressions().find(|item| item.key().named_key_without_resolving().is_some() && item.key().named_key_without_resolving().unwrap() == name.as_ref() && item.is_available()).map(|item| item.value())
    }

    pub fn items(&self) -> Vec<(&Expression, &Expression)> {
        self.dictionary_literal().expressions().map(|e| (e.key(), e.value())).collect()
    }
}

impl NamedIdentifiable for Config {

    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }

    fn name(&self) -> &str {
        if let Some(identifier) = self.identifier() {
            identifier.name()
        } else {
            self.keyword().name()
        }
    }
}

impl InfoProvider for Config {

    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Write for Config {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}