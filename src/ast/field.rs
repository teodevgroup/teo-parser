use std::cell::RefCell;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::type_expr::TypeExpr;
use crate::ast::identifier::Identifier;
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;

#[derive(Debug, Copy, Clone)]
pub(crate) enum FieldHint {
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
pub(crate) enum FieldClass {
    ModelPrimitiveField(ModelPrimitiveFieldSettings),
    ModelRelation(ModelRelationSettings),
    ModelProperty(ModelPropertyFieldSettings),
    InterfaceField,
    ConfigDeclarationField,
}

impl FieldClass {

    pub(crate) fn is_model_relation(&self) -> bool {
        self.as_model_relation().is_some()
    }

    pub(crate) fn as_model_relation(&self) -> Option<&ModelRelationSettings> {
        match self {
            FieldClass::ModelRelation(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn is_model_primitive_field(&self) -> bool {
        self.as_model_primitive_field().is_some()
    }

    pub(crate) fn as_model_primitive_field(&self) -> Option<&ModelPrimitiveFieldSettings> {
        match self {
            FieldClass::ModelPrimitiveField(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn is_model_property(&self) -> bool {
        self.as_model_property().is_some()
    }

    pub(crate) fn as_model_property(&self) -> Option<&ModelPropertyFieldSettings> {
        match self {
            FieldClass::ModelProperty(s) => Some(s),
            _ => None,
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
        self.is_model_relation() ||
        self.is_model_property()
    }

    pub(crate) fn reference_type(&self) -> ReferenceType {
        match self {
            FieldClass::ModelPrimitiveField(_) => ReferenceType::ModelFieldDecorator,
            FieldClass::ModelRelation(_) => ReferenceType::ModelRelationDecorator,
            FieldClass::ModelProperty(_) => ReferenceType::ModelPropertyDecorator,
            FieldClass::InterfaceField => ReferenceType::InterfaceFieldDecorator,
            FieldClass::ConfigDeclarationField => ReferenceType::Default,
        }
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
    pub(crate) empty_decorators_spans: Vec<Span>,
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
