use std::cell::RefCell;
use indexmap::{IndexMap, indexmap};
use serde::{Serialize, Serializer};
use crate::ast::doc_comment::DocComment;
use crate::ast::field::Field;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::format::Writer;
use crate::r#type::Type;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(InterfaceDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) generics_declaration: Option<usize>,
    pub(crate) generics_constraint: Option<usize>,
    pub(crate) extends: Vec<usize>,
    pub(crate) fields: Vec<usize>,
    pub(crate) resolved: RefCell<Option<InterfaceDeclarationResolved>>,
);

impl_container_node_defaults!(InterfaceDeclaration, named, availability);

node_children_iter!(InterfaceDeclaration, TypeExpr, ExtendsIter, extends);

node_children_iter!(InterfaceDeclaration, Field, FieldsIter, fields);

impl InterfaceDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(generics_declaration, GenericsDeclaration);

    node_optional_child_fn!(generics_constraint, GenericsConstraint);

    node_children_iter_fn!(extends, ExtendsIter);

    node_children_iter_fn!(fields, FieldsIter);

    pub fn shape(&self, generics: &Vec<Type>) -> Option<&Type> {
        self.resolved().map.get(generics)
    }

    pub fn set_shape(&self, generics: Vec<Type>, input: Type) {
        self.resolved_mut().map.insert(generics, input);
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

#[derive(Debug, Clone)]
pub struct InterfaceDeclarationResolved {
    pub map: IndexMap<Vec<Type>, Type>,
}

#[derive(Serialize)]
pub struct InterfaceDeclarationShapeResolvedItemRef<'a> {
    key: &'a Vec<Type>,
    value: &'a Type,
}

impl Serialize for InterfaceDeclarationResolved {

    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.collect_seq(self.map.iter().map(|(key, value)| InterfaceDeclarationShapeResolvedItemRef {
            key,
            value
        }))
    }
}

impl InterfaceDeclarationResolved {

    pub fn new() -> Self {
        Self {
            map: indexmap! {}
        }
    }
}

impl Write for InterfaceDeclaration {
    fn write(&self, writer: &mut Writer) {
        writer.write_children(self, self.children.values())
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}