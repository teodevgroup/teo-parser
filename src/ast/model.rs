use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::field::Field;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Model {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) decorators: Vec<Decorator>,
    pub(crate) empty_decorator_spans: Vec<Span>,
    pub(crate) identifier: Identifier,
    pub(crate) fields: Vec<Field>,
    pub(crate) empty_field_decorator_spans: Vec<Span>,
    pub(crate) unattached_field_decorators: Vec<Decorator>,
}

impl Model {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    // pub(crate) fn sorted_fields(&self) -> Vec<&Field> {
    //     self.fields.iter().sorted_by(|a, b| if a.resolved().class.is_primitive_field() {
    //         Ordering::Greater
    //     } else if b.resolved().class.is_relation() {
    //         Ordering::Less
    //     } else {
    //         Ordering::Less
    //     }).collect()
    // }

    pub(crate) fn field_named(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name() == key)
    }
}
