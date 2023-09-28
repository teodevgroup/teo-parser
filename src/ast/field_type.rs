use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::arity::Arity;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) enum FieldTypeResolved {
    Builtin,
    Enum(Vec<usize>),
    Model(Vec<usize>),
    Interface(Vec<usize>),
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

    pub(crate) fn is_interface(&self) -> bool {
        match self {
            FieldTypeResolved::Interface(_) => true,
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

    pub(crate) fn interface_path(&self) -> Option<&Vec<usize>> {
        match self {
            FieldTypeResolved::Interface(path) => Some(path),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct FieldType {
    pub(crate) span: Span,
    pub(crate) identifier_path: IdentifierPath,
    pub(crate) generics: Vec<FieldType>,
    pub(crate) arity: Arity,
    pub(crate) item_required: bool,
    pub(crate) collection_required: bool,
    pub(crate) resolved: RefCell<Option<FieldTypeResolved>>,
}

impl FieldType {

    pub(crate) fn resolve(&self, resolved: FieldTypeResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }
}

impl Display for FieldType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.identifier_path, f)?;
        if self.generics.len() > 0 {
            f.write_str("<")?;
        }
        for (index, arg) in self.generics.iter().enumerate() {
            Display::fmt(arg, f)?;
            if index != self.generics.len() - 1 {
                f.write_str(", ")?;
            }
        }
        if self.generics.len() > 0 {
            f.write_str(">")?;
        }
        if !self.item_required {
            f.write_str("?")?;
        }
        if self.arity != Arity::Scalar {
            match self.arity {
                Arity::Array => f.write_str("[]")?,
                Arity::Dictionary => f.write_str("{}")?,
                _ => ()
            };
            if !self.collection_required {
                f.write_str("?")?;
            }
        }
        Ok(())
    }
}