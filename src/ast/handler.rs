use std::cell::RefCell;
use serde::Serialize;
use crate::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::type_expr::{TypeExpr};
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;

#[derive(Debug)]
pub struct HandlerGroupDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub handler_declarations: Vec<HandlerDeclaration>,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
}

impl Identifiable for HandlerGroupDeclaration {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for HandlerGroupDeclaration {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for HandlerGroupDeclaration {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for HandlerGroupDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}

#[derive(Debug)]
pub struct HandlerDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub decorators: Vec<Decorator>,
    pub empty_decorators_spans: Vec<Span>,
    pub identifier: Identifier,
    pub input_type: TypeExpr,
    pub output_type: TypeExpr,
    pub input_format: HandlerInputFormat,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
}

impl HandlerDeclaration {

    pub fn name(&self) -> &str {
        self.string_path.last().map(AsRef::as_ref).unwrap()
    }

}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum HandlerInputFormat {
    Json,
    Form,
}

impl HandlerInputFormat {

    pub fn is_json(&self) -> bool {
        match self {
            HandlerInputFormat::Json => true,
            _ => false,
        }
    }

    pub fn is_form(&self) -> bool {
        match self {
            HandlerInputFormat::Form => true,
            _ => false,
        }
    }
}

impl Identifiable for HandlerDeclaration {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for HandlerDeclaration {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for HandlerDeclaration {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for HandlerDeclaration {
    fn namespace_skip(&self) -> usize {
        2
    }
}