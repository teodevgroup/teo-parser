use std::cell::RefCell;
use std::collections::BTreeMap;
use maplit::btreemap;
use serde::Serialize;
use crate::ast::doc_comment::DocComment;
use crate::ast::field::Field;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::ast::partial_field::PartialField;
use crate::format::Writer;
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::r#type::Type;
use crate::traits::info_provider::InfoProvider;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

use super::decorator::Decorator;
use super::span::Span;

declare_container_node!(InterfaceDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) generics_declaration: Option<usize>,
    pub(crate) generics_constraint: Option<usize>,
    pub(crate) extends: Vec<usize>,
    pub(crate) fields: Vec<usize>,
    pub(crate) partial_fields: Vec<usize>,
    pub(crate) decorators: Vec<usize>,
    pub(crate) empty_decorator_spans: Vec<Span>,
    pub(crate) empty_field_decorator_spans: Vec<Span>,
    pub(crate) unattached_field_decorators: Vec<Decorator>,
    pub(crate) resolved: RefCell<Option<InterfaceDeclarationResolved>>,
);

impl_container_node_defaults!(InterfaceDeclaration, named, availability);

node_children_iter!(InterfaceDeclaration, TypeExpr, ExtendsIter, extends);

node_children_iter!(InterfaceDeclaration, Field, FieldsIter, fields);

node_children_iter!(InterfaceDeclaration, PartialField, PartialFieldsIter, partial_fields);

node_children_iter!(InterfaceDeclaration, Decorator, DecoratorsIter, decorators);

impl InterfaceDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(generics_declaration, GenericsDeclaration);

    node_optional_child_fn!(generics_constraint, GenericsConstraint);

    node_children_iter_fn!(extends, ExtendsIter);

    node_children_iter_fn!(fields, FieldsIter);

    node_children_iter_fn!(partial_fields, PartialFieldsIter);

    node_children_iter_fn!(decorators, DecoratorsIter);

    pub fn shape_from_generics(&self, generics: &Vec<Type>) -> SynthesizedShape {
        let map = self.calculate_generics_map(generics);
        self.resolved().shape().replace_generics(&map)
    }

    pub fn calculate_generics_map(&self, types: &Vec<Type>) -> BTreeMap<String, Type> {
        if let Some(generics_declaration) = self.generics_declaration() {
            generics_declaration.calculate_generics_map(types)
        } else {
            btreemap!{}
        }
    }
}

impl InfoProvider for InterfaceDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Resolve<InterfaceDeclarationResolved> for InterfaceDeclaration {
    fn resolved_ref_cell(&self) -> &RefCell<Option<InterfaceDeclarationResolved>> {
        &self.resolved
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InterfaceDeclarationResolved {
    pub base_shape: SynthesizedShape,
    #[serde(skip)]
    pub shape: Option<SynthesizedShape>,
}

impl InterfaceDeclarationResolved {

    pub fn base_shape(&self) -> &SynthesizedShape {
        &self.base_shape
    }

    pub fn shape(&self) -> &SynthesizedShape {
        self.shape.as_ref().unwrap()
    }
}

impl InterfaceDeclarationResolved {

    pub fn new(base_shape: SynthesizedShape) -> Self {
        Self {
            base_shape,
            shape: None,
        }
    }
}

impl Write for InterfaceDeclaration {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}