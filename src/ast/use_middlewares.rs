use std::fmt::Display;
use crate::ast::availability::Availability;
use crate::ast::literals::ArrayLiteral;
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;

#[derive(Debug)]
pub struct UseMiddlewaresBlock {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub namespace_string_path: Vec<String>,
    pub array_literal: ArrayLiteral,
}

impl Identifiable for UseMiddlewaresBlock {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for UseMiddlewaresBlock {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for UseMiddlewaresBlock {
    fn define_availability(&self) -> Availability {
        Availability::default()
    }

    fn actual_availability(&self) -> Availability {
        Availability::default()
    }
}

impl InfoProvider for UseMiddlewaresBlock {
    fn namespace_skip(&self) -> usize {
        1
    }
}