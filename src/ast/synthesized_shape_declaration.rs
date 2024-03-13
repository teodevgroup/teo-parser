use std::cell::RefCell;
use std::collections::BTreeMap;
use indexmap::IndexMap;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::ast::doc_comment::DocComment;
use crate::ast::field::Field;
use crate::ast::identifier::Identifier;
use crate::ast::partial_field::PartialField;
use crate::ast::synthesized_shape_field_declaration::SynthesizedShapeFieldDeclaration;
use crate::format::Writer;
use crate::r#type::Type;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(SynthesizedShapeDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) static_fields: Vec<usize>,
    pub(crate) dynamic_fields: Vec<usize>,
    pub(crate) partial_static_fields: Vec<usize>,
    pub(crate) builtin: bool,
    pub(crate) resolved: RefCell<Option<SynthesizedShapeDeclarationResolved>>,
);

impl_container_node_defaults!(SynthesizedShapeDeclaration, named, availability);

node_children_iter!(SynthesizedShapeDeclaration, Field, StaticFieldsIter, static_fields);

node_children_iter!(SynthesizedShapeDeclaration, SynthesizedShapeFieldDeclaration, DynamicFieldsIter, dynamic_fields);

node_children_iter!(SynthesizedShapeDeclaration, PartialField, PartialFieldsIter, partial_static_fields);

impl SynthesizedShapeDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_children_iter_fn!(static_fields, StaticFieldsIter);

    node_children_iter_fn!(dynamic_fields, DynamicFieldsIter);

    node_children_iter_fn!(partial_fields, PartialFieldsIter);
}

impl Resolve<SynthesizedShapeDeclarationResolved> for SynthesizedShapeDeclaration {
    fn resolved_ref_cell(&self) -> &RefCell<Option<SynthesizedShapeDeclarationResolved>> {
        &self.resolved
    }
}

impl Write for SynthesizedShapeDeclaration {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct SynthesizedShapeDeclarationResolved {
    pub base_shape: IndexMap<String, Type>,
}