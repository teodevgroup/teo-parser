use std::cell::RefCell;
use crate::ast::span::Span;
use crate::ast::doc_comment::DocComment;
use crate::ast::decorator::Decorator;
use crate::ast::type_expr::TypeExpr;
use crate::ast::identifier::Identifier;
use crate::ast::reference_space::ReferenceSpace;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::format::Writer;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

#[derive(Debug, Copy, Clone)]
pub enum FieldHint {
    ModelField,
    InterfaceField,
}

#[derive(Debug, Copy, Clone)]
pub struct ModelPrimitiveFieldSettings {
    pub dropped: bool,
    pub r#virtual: bool,
}

#[derive(Debug, Copy, Clone)]
pub struct ModelRelationSettings {
    pub direct: bool,
}

#[derive(Debug, Copy, Clone)]
pub struct ModelPropertyFieldSettings {
   pub cached: bool,
}

#[derive(Debug, Copy, Clone)]
pub enum FieldClass {
    ModelPrimitiveField(ModelPrimitiveFieldSettings),
    ModelRelation(ModelRelationSettings),
    ModelProperty(ModelPropertyFieldSettings),
    InterfaceField,
    ConfigDeclarationField,
}

impl FieldClass {

    pub fn is_model_relation(&self) -> bool {
        self.as_model_relation().is_some()
    }

    pub fn as_model_relation(&self) -> Option<&ModelRelationSettings> {
        match self {
            FieldClass::ModelRelation(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_model_primitive_field(&self) -> bool {
        self.as_model_primitive_field().is_some()
    }

    pub fn as_model_primitive_field(&self) -> Option<&ModelPrimitiveFieldSettings> {
        match self {
            FieldClass::ModelPrimitiveField(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_model_property(&self) -> bool {
        self.as_model_property().is_some()
    }

    pub fn as_model_property(&self) -> Option<&ModelPropertyFieldSettings> {
        match self {
            FieldClass::ModelProperty(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_interface_field(&self) -> bool {
        match self {
            FieldClass::InterfaceField => true,
            _ => false,
        }
    }

    pub fn is_model_field(&self) -> bool {
        self.is_model_field() ||
        self.is_model_relation() ||
        self.is_model_property()
    }

    pub fn reference_type(&self) -> ReferenceSpace {
        match self {
            FieldClass::ModelPrimitiveField(_) => ReferenceSpace::ModelFieldDecorator,
            FieldClass::ModelRelation(_) => ReferenceSpace::ModelRelationDecorator,
            FieldClass::ModelProperty(_) => ReferenceSpace::ModelPropertyDecorator,
            FieldClass::InterfaceField => ReferenceSpace::InterfaceFieldDecorator,
            FieldClass::ConfigDeclarationField => ReferenceSpace::Default,
        }
    }
}

#[derive(Debug)]
pub struct FieldResolved {
    pub class: FieldClass,
}

declare_container_node!(Field, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) decorators: Vec<usize>,
    pub(crate) empty_decorator_spans: Vec<Span>,
    pub(crate) identifier: usize,
    pub(crate) type_expr: usize,
    pub(crate) resolved: RefCell<Option<FieldResolved>>,
);

impl_container_node_defaults!(Field, named, availability);

node_children_iter!(Field, Decorator, DecoratorsIter, decorators);

impl Field {

    node_optional_child_fn!(comment, DocComment);

    node_children_iter_fn!(decorators, DecoratorsIter);

    node_child_fn!(identifier, Identifier);

    node_child_fn!(type_expr, TypeExpr);
}

impl InfoProvider for Field {
    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Resolve<FieldResolved> for Field {
    fn resolved_ref_cell(&self) -> &RefCell<Option<FieldResolved>> {
        &self.resolved
    }
}

impl Write for Field {
    fn write(&self, writer: &mut Writer) {
        writer.write_children(self, self.children.values())
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}

