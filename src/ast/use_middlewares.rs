use std::fmt::Display;
use crate::ast::availability::Availability;
use crate::ast::identifiable::Identifiable;
use crate::ast::info_provider::InfoProvider;
use crate::ast::literals::ArrayLiteral;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct UseMiddlewaresBlock {
    pub span: Span,
    pub path: Vec<usize>,
    pub namespace_string_path: Vec<String>,
    pub array_literal: ArrayLiteral,
}

impl Identifiable for UseMiddlewaresBlock {

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
        let mut ns = self.namespace_str_path();
        ns.push("middlewares");
        ns
    }
}

impl InfoProvider for UseMiddlewaresBlock {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.namespace_string_path.iter().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        Availability::default()
    }
}