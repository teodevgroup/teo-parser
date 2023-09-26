use std::sync::Mutex;
use crate::ast::argument::Argument;
use crate::ast::argument_list::ArgumentList;
use crate::ast::expr::ExpressionKind;
use crate::ast::span::Span;

#[derive(Debug, Clone)]
pub struct DecoratorResolved {
    string_path: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Decorator {
    pub(crate) expression: ExpressionKind,
    pub(crate) span: Span,
    pub(crate) arguments: Option<ArgumentList>,
    pub(crate) resolved: Mutex<Option<DecoratorResolved>>,
}

impl Decorator {

    pub(crate) fn new(expression: ExpressionKind, span: Span, arguments: Option<ArgumentList>) -> Self {
        Self { expression, span, arguments, resolved: Mutex::new(None) }
    }

    pub(crate) fn get_argument_list(&self) -> &Vec<Argument> {
        static ARGUMENTS: Vec<Argument> = vec![];
        match &self.arguments {
            Some(argument_list) => &argument_list.arguments,
            None => &ARGUMENTS,
        }
    }
}
