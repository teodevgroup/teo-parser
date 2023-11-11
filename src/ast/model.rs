use std::cell::RefCell;
use indexmap::IndexMap;
use serde::{Serialize, Serializer};
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::field::Field;
use crate::ast::handler::HandlerDeclaration;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::r#type::synthesized_enum::SynthesizedEnum;
use crate::r#type::synthesized_enum_reference::SynthesizedEnumReferenceKind;
use crate::r#type::synthesized_shape_reference::SynthesizedShapeReferenceKind;
use crate::r#type::Type;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::resolved::Resolve;

#[derive(Debug)]
pub struct Model {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub decorators: Vec<Decorator>,
    pub empty_decorator_spans: Vec<Span>,
    pub identifier: Identifier,
    pub fields: Vec<Field>,
    pub empty_field_decorator_spans: Vec<Span>,
    pub unattached_field_decorators: Vec<Decorator>,
    pub handlers: Vec<HandlerDeclaration>,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
    pub resolved: RefCell<Option<ModelResolved>>,
}

#[derive(Debug, Serialize)]
pub struct ModelResolved {
    pub actual_availability: Availability,
    pub enums: IndexMap<SynthesizedEnumReferenceKind, SynthesizedEnum>,
    pub shapes: IndexMap<(SynthesizedShapeReferenceKind, Option<String>), Type>,
}

impl ModelResolved {

    pub fn get(&self, key: SynthesizedShapeReferenceKind) -> Option<&Type> {
        self.shapes.get(&(key, None))
    }
}

impl Identifiable for Model {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for Model {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl Resolve<ModelResolved> for Model {
    fn resolved_ref_cell(&self) -> &RefCell<Option<ModelResolved>> {
        &self.resolved
    }
}

impl HasAvailability for Model {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for Model {
    fn namespace_skip(&self) -> usize {
        1
    }
}