use crate::ast::generics_declaration::GenericsDeclaration;
use crate::ast::identifier::Identifier;
use crate::ast::interface_type::InterfaceType;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct InterfaceDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) identifier: Identifier,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) extends: Vec<InterfaceType>,
    pub(crate) items: Vec<InterfaceItem>,
}

impl InterfaceDeclaration {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub(crate) fn args(&self) -> &Vec<InterfaceType> {
        &self.name.args
    }
}

#[derive(Debug)]
pub(crate) struct InterfaceItem {
    pub(crate) span: Span,
    pub(crate) name: Identifier,
    pub(crate) kind: InterfaceType,
}