use std::cell::RefCell;
use crate::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::type_expr::TypeExpr;
use crate::ast::identifier::Identifier;
use crate::ast::reference_space::ReferenceSpace;
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::resolved::Resolve;

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

#[derive(Debug)]
pub struct Field {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub decorators: Vec<Decorator>,
    pub empty_decorators_spans: Vec<Span>,
    pub identifier: Identifier,
    pub type_expr: TypeExpr,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
    pub resolved: RefCell<Option<FieldResolved>>,
}

impl Identifiable for Field {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for Field {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for Field {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
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

