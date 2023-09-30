use std::cell::RefCell;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::r#type::{TypeExpr, TypeItem};
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug, Copy, Clone)]
pub(crate) enum FieldHint {
    ModelField,
    InterfaceField,
}

#[derive(Debug, Copy, Clone)]
pub(crate) enum FieldClass {
    ModelPrimitiveField,
    ModelDroppedPrimitiveField,
    ModelRelation,
    ModelProperty,
    InterfaceField,
}

impl FieldClass {
    pub(crate) fn is_model_relation(&self) -> bool {
        match self {
            FieldClass::ModelRelation => true,
            _ => false,
        }
    }

    pub(crate) fn is_model_primitive_field(&self) -> bool {
        match self {
            FieldClass::ModelPrimitiveField => true,
            _ => false,
        }
    }

    pub(crate) fn is_model_dropped_primitive_field(&self) -> bool {
        match self {
            FieldClass::ModelDroppedPrimitiveField => true,
            _ => false,
        }
    }

    pub(crate) fn is_model_property(&self) -> bool {
        match self {
            FieldClass::ModelProperty => true,
            _ => false,
        }
    }

    pub(crate) fn is_interface_field(&self) -> bool {
        match self {
            FieldClass::InterfaceField => true,
            _ => false,
        }
    }

    pub(crate) fn is_model_field(&self) -> bool {
        self.is_model_field() ||
        self.is_model_dropped_primitive_field() ||
        self.is_model_relation() ||
        self.is_model_property()
    }
}

#[derive(Debug)]
pub(crate) struct FieldResolved {
    pub(crate) class: FieldClass,
}

#[derive(Debug)]
pub(crate) struct Field {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) decorators: Vec<Decorator>,
    pub(crate) identifier: Identifier,
    pub(crate) type_expr: TypeExpr,
    pub(crate) resolved: RefCell<Option<FieldResolved>>,
}

impl Field {

    pub(crate) fn name(&self) -> &str {
        self.identifier.name.as_str()
    }

    pub(crate) fn resolve(&self, resolved: FieldResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub(crate) fn resolved(&self) -> &FieldResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }
}
