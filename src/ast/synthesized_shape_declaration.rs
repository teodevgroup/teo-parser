use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::ast::doc_comment::DocComment;
use crate::ast::field::Field;
use crate::ast::identifier::Identifier;
use crate::ast::synthesized_shape_field_declaration::SynthesizedShapeFieldDeclaration;
use crate::format::Writer;
use crate::traits::write::Write;

declare_container_node!(SynthesizedShapeDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) static_fields: Vec<usize>,
    pub(crate) dynamic_fields: Vec<usize>,
);

impl_container_node_defaults!(SynthesizedShapeDeclaration, named, availability);

node_children_iter!(SynthesizedShapeDeclaration, Field, StaticFieldsIter, static_fields);

node_children_iter!(SynthesizedShapeDeclaration, SynthesizedShapeFieldDeclaration, DynamicFieldsIter, dynamic_fields);

impl SynthesizedShapeDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_children_iter_fn!(static_fields, StaticFieldsIter);

    node_children_iter_fn!(dynamic_fields, DynamicFieldsIter);
}

impl Write for SynthesizedShapeDeclaration {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}