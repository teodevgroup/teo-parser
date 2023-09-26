use std::sync::Mutex;
use crate::ast::argument::Argument;
use crate::ast::argument_list::ArgumentList;
use crate::ast::expr::ExpressionKind;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct DecoratorResolved {
    string_path: Vec<String>,
}

#[derive(Debug)]
pub struct Decorator {
    pub(crate) expression: ExpressionKind,
    pub(crate) span: Span,
    pub(crate) arguments: ArgumentList,
    pub(crate) resolved: Mutex<Option<DecoratorResolved>>,
}

impl Decorator {

    pub(crate) fn new(expression: ExpressionKind, span: Span, arguments: ArgumentList) -> Self {
        Self { expression, span, arguments, resolved: Mutex::new(None) }
    }

    pub(crate) fn get_argument_list(&self) -> &Vec<Argument> {
        &self.arguments.arguments
    }
}
