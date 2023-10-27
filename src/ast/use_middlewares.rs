use std::fmt::Display;
use crate::ast::literals::ArrayLiteral;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct UseMiddlewaresBlock {
    pub span: Span,
    pub path: Vec<usize>,
    pub namespace_string_path: Vec<String>,
    pub array_literal: ArrayLiteral,
}

impl UseMiddlewaresBlock {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.namespace_string_path.iter().map(AsRef::as_ref).collect()
    }
}