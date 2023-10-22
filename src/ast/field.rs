use std::cell::RefCell;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::type_expr::TypeExpr;
use crate::ast::identifier::Identifier;
use crate::ast::info_provider::InfoProvider;
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;

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

    pub fn reference_type(&self) -> ReferenceType {
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
pub struct FieldResolved {
    pub class: FieldClass,
    pub actual_availability: Availability,
}

#[derive(Debug)]
pub struct Field {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub define_availability: Availability,
    pub comment: Option<Comment>,
    pub decorators: Vec<Decorator>,
    pub empty_decorators_spans: Vec<Span>,
    pub identifier: Identifier,
    pub type_expr: TypeExpr,
    pub resolved: RefCell<Option<FieldResolved>>,
}

impl Field {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn name(&self) -> &str {
        self.identifier.name.as_str()
    }

    pub fn resolve(&self, resolved: FieldResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &FieldResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }

    pub fn is_available(&self) -> bool {
        self.define_availability.contains(self.resolved().actual_availability)
    }
}

impl InfoProvider for Field {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(2).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}
