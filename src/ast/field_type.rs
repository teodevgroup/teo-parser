use std::cell::RefCell;
use std::sync::Mutex;
use crate::ast::arity::Arity;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) enum FieldTypeResolved {
    Builtin,
    Enum(Vec<usize>),
    Model(Vec<usize>),
}

impl FieldTypeResolved {

    pub(crate) fn is_enum(&self) -> bool {
        match self {
            FieldTypeResolved::Enum(_) => true,
            _ => false,
        }
    }

    pub(crate) fn is_builtin(&self) -> bool {
        match self {
            FieldTypeResolved::Builtin => true,
            _ => false,
        }
    }

    pub(crate) fn is_model(&self) -> bool {
        match self {
            FieldTypeResolved::Model(_) => true,
            _ => false,
        }
    }

    pub(crate) fn model_path(&self) -> Option<&Vec<usize>> {
        match self {
            FieldTypeResolved::Model(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn enum_path(&self) -> Option<&Vec<usize>> {
        match self {
            FieldTypeResolved::Enum(path) => Some(path),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct FieldType {
    pub(crate) span: Span,
    pub(crate) identifier_path: IdentifierPath,
    pub(crate) arity: Arity,
    pub(crate) item_required: bool,
    pub(crate) collection_required: bool,
    pub(crate) resolved: RefCell<Option<FieldTypeResolved>>,
}

impl FieldType {

    pub(crate) fn resolve(&self, resolved: FieldTypeResolved) {
        let mut binding = self.resolved.lock().unwrap();
        let mut_ref = binding.as_mut().unwrap();
        *mut_ref = resolved;
    }
}
