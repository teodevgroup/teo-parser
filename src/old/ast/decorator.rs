use crate::ast::accessible::Accessible;
use crate::ast::argument::{Argument, ArgumentList};
use crate::ast::expression::ExpressionKind;
use crate::ast::span::Span;

#[derive(Debug, Clone)]
pub struct ASTDecorator {
    pub(crate) expression: ExpressionKind,
    pub(crate) span: Span,
    pub(crate) resolved: bool,
    pub(crate) accessible: Option<Accessible>,
    pub(crate) arguments: Option<ArgumentList>,
}

impl ASTDecorator {
    pub(crate) fn new(expression: ExpressionKind, span: Span) -> Self {
        Self { expression, span, resolved: false, accessible: None, arguments: None }
    }

    pub(crate) fn get_argument_list(&self) -> &Vec<Argument> {
        static ARGUMENTS: Vec<Argument> = vec![];
        match &self.arguments {
            Some(argument_list) => &argument_list.arguments,
            None => &ARGUMENTS,
        }
    }
}
