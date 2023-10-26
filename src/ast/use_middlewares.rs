use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::literals::ArrayLiteral;
use crate::ast::span::Span;
use crate::ast::unit::Unit;

#[derive(Debug)]
pub struct UseMiddlewaresBlock {
    pub span: Span,
    pub path: Vec<usize>,
    pub array_literal: ArrayLiteral,
}

impl UseMiddlewaresBlock {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }
}