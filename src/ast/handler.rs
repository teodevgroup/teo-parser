use std::cell::RefCell;
use serde::Serialize;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::identifiable::Identifiable;
use crate::ast::type_expr::{TypeExpr};
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use super::info_provider::InfoProvider;

#[derive(Debug)]
pub struct HandlerGroupDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub handler_declarations: Vec<HandlerDeclaration>,
    pub define_availability: Availability,
}

impl HandlerGroupDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
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
}

impl HandlerDeclaration {

    pub fn name(&self) -> &str {
        self.string_path.last().map(AsRef::as_ref).unwrap()
    }

    pub fn handler_group_id(&self) -> usize {
        *self.path.get(self.path.len() - 2).unwrap()
    }

    pub fn handler_group_name(&self) -> &str {
        self.string_path.get(self.path.len() - 2).unwrap()
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

    fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    fn path(&self) -> &Vec<usize> {
        &self.path
    }

    fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }
}

impl InfoProvider for HandlerDeclaration {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(2).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        Availability::default()
    }
}
