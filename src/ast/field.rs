use std::cell::RefCell;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::field_type::FieldType;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug, Copy, Clone)]
pub(crate) enum FieldClass {
    Field,
    DroppedField,
    Relation,
    Property,
}

impl FieldClass {
    pub(crate) fn is_relation(&self) -> bool {
        match self {
            FieldClass::Relation => true,
            _ => false,
        }
    }

    pub(crate) fn is_primitive_field(&self) -> bool {
        match self {
            FieldClass::Field => true,
            _ => false,
        }
    }

    pub(crate) fn is_dropped(&self) -> bool {
        match self {
            FieldClass::DroppedField => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub(crate) struct FieldResolved {
    pub(crate) class: FieldClass,
}

#[derive(Debug)]
pub(crate) struct Field {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) decorators: Vec<Decorator>,
    pub(crate) identifier: Identifier,
    pub(crate) field_type: FieldType,
    pub(crate) resolved: RefCell<Option<FieldResolved>>,
}

impl Field {

    pub(crate) fn name(&self) -> &str {
        self.identifier.name.as_str()
    }
}
