use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::field::Field;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct ConfigDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) identifier: Identifier,
    pub(crate) fields: Vec<Field>,
    pub(crate) define_availability: Availability,
}

impl ConfigDeclaration {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }
}