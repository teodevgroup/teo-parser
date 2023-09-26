use crate::ast::identifier::Identifier;
use crate::ast::interface_type::InterfaceType;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct InterfaceDeclaration {
    pub(crate) path: Vec<usize>,
    pub(crate) name: InterfaceType,
    pub(crate) extends: Vec<InterfaceType>,
    pub(crate) items: Vec<InterfaceItemDeclaration>,
    pub(crate) span: Span,
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
pub(crate) struct InterfaceItemDeclaration {
    pub(crate) span: Span,
    pub(crate) name: Identifier,
    pub(crate) kind: InterfaceType,
}