use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::field::Field;
use crate::ast::identifiable::Identifiable;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct ConfigDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub fields: Vec<Field>,
    pub define_availability: Availability,
}

impl ConfigDeclaration {
    
    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    pub fn get_field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.identifier.name() == name)
    }
}

impl Identifiable for ConfigDeclaration {

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
        self.string_path.iter().map(|s| s.as_str()).collect()
    }
}