use std::cell::RefCell;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::type_expr::{TypeExpr, TypeShape};
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

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
    pub resolved: RefCell<Option<HandlerDeclarationResolved>>,
}

impl HandlerDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(2).rev().map(AsRef::as_ref).collect()
    }

    pub fn handler_group_id(&self) -> usize {
        *self.path.get(self.path.len() - 2).unwrap()
    }

    pub fn resolve(&self, resolved: HandlerDeclarationResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &HandlerDeclarationResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
pub struct HandlerDeclarationResolved {
    pub input_shape: TypeShape,
    pub output_shape: TypeShape,
}
