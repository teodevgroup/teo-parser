use std::cell::RefCell;
use indexmap::IndexMap;
use serde::{Serialize};
use crate::ast::doc_comment::DocComment;
use crate::ast::decorator::Decorator;
use crate::ast::field::Field;
use crate::ast::handler::HandlerDeclaration;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::ast::partial_field::PartialField;
use crate::format::Writer;
use crate::r#type::synthesized_enum::SynthesizedEnum;
use crate::r#type::synthesized_enum_reference::SynthesizedEnumReferenceKind;
use crate::r#type::synthesized_interface_enum::SynthesizedInterfaceEnum;
use crate::r#type::synthesized_interface_enum_reference::SynthesizedInterfaceEnumReferenceKind;
use crate::r#type::synthesized_shape_reference::SynthesizedShapeReferenceKind;
use crate::r#type::Type;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(Model, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) decorators: Vec<usize>,
    pub(crate) empty_decorator_spans: Vec<Span>,
    pub(crate) identifier: usize,
    pub(crate) fields: Vec<usize>,
    pub(crate) partial_fields: Vec<usize>,
    pub(crate) empty_field_decorator_spans: Vec<Span>,
    pub(crate) unattached_field_decorators: Vec<Decorator>,
    pub(crate) handlers: Vec<usize>,
    pub(crate) resolved: RefCell<Option<ModelResolved>>,
);

impl_container_node_defaults!(Model, named, availability);

node_children_iter!(Model, Decorator, DecoratorsIter, decorators);

node_children_iter!(Model, Field, FieldsIter, fields);

node_children_iter!(Model, PartialField, PartialFieldsIter, partial_fields);

node_children_iter!(Model, HandlerDeclaration, HandlersIter, handlers);

impl Model {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_children_iter_fn!(decorators, DecoratorsIter);

    node_children_iter_fn!(fields, FieldsIter);

    node_children_iter_fn!(partial_fields, PartialFieldsIter);

    node_children_iter_fn!(handlers, HandlersIter);
}

#[derive(Debug, Serialize, Clone)]
pub struct ModelResolved {
    pub enums: IndexMap<SynthesizedEnumReferenceKind, SynthesizedEnum>,
    pub interface_enums: IndexMap<SynthesizedInterfaceEnumReferenceKind, SynthesizedInterfaceEnum>,
    pub shapes: IndexMap<(SynthesizedShapeReferenceKind, Option<String>), Type>,
}

impl ModelResolved {
    
    pub fn new() -> Self {
        Self {
            enums: Default::default(),
            interface_enums: Default::default(),
            shapes: Default::default(),
        }
    }

    pub fn get(&self, key: SynthesizedShapeReferenceKind) -> Option<&Type> {
        self.shapes.get(&(key, None))
    }

    pub fn get_without(&self, key: SynthesizedShapeReferenceKind, without: &str) -> Option<&Type> {
        self.shapes.get(&(key, Some(without.to_owned())))
    }
}

impl Resolve<ModelResolved> for Model {
    fn resolved_ref_cell(&self) -> &RefCell<Option<ModelResolved>> {
        &self.resolved
    }
}

impl InfoProvider for Model {
    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Write for Model {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}