use std::cell::RefCell;
use crate::ast::argument_list::ArgumentList;
use crate::ast::expr::ExpressionKind;
use crate::ast::span::Span;

#[derive(Debug, PartialEq, Eq)]
pub enum DecoratorClass {
    EnumDecorator,
    EnumMemberDecorator,
    ModelDecorator,
    ModelFieldDecorator,
    ModelRelationDecorator,
    ModelPropertyDecorator,
    InterfaceDecorator,
    InterfaceFieldDecorator,
}

#[derive(Debug)]
pub struct DecoratorResolved {
    pub(crate) path: Vec<usize>,
    pub(crate) class: DecoratorClass,
    pub(crate) arguments: ArgumentList,
}

#[derive(Debug)]
pub struct Decorator {
    pub(crate) span: Span,
    pub(crate) expression: ExpressionKind,
    pub(crate) resolved: RefCell<Option<DecoratorResolved>>,
}

impl Decorator {

    pub(crate) fn resolved(&self) -> &DecoratorResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }
}
