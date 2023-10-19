use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::function_declaration::FunctionDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct StructDeclaration {
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) define_availability: Availability,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
    pub function_declarations: Vec<FunctionDeclaration>,
    pub(crate) span: Span,
}

impl StructDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }
}