use std::fmt::{Display, Formatter};
use regex::Regex;
use teo_teon::value::Value;
use crate::ast::argument_list::ArgumentList;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct NumericLiteral {
    pub(crate) value: Value,
    pub(crate) span: Span,
}

impl Display for NumericLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.value, f)
    }
}


#[derive(Debug)]
pub(crate) struct StringLiteral {
    pub(crate) value: String,
    pub(crate) span: Span,
}

impl Display for StringLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.value)
    }
}

#[derive(Debug)]
pub(crate) struct RegexLiteral {
    pub(crate) value: Regex,
    pub(crate) span: Span,
}

impl Display for RegexLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("/")?;
        f.write_str(self.value.as_str())?;
        f.write_str("/")
    }
}

#[derive(Debug)]
pub(crate) struct BoolLiteral {
    pub(crate) value: bool,
    pub(crate) span: Span,
}

impl Display for BoolLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.value, f)
    }
}

#[derive(Debug, Default)]
pub(crate) struct NullLiteral {
    pub(crate) span: Span,
}

impl Display for NullLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("null")
    }
}

#[derive(Debug)]
pub(crate) struct EnumVariantLiteral {
    pub(crate) span: Span,
    pub(crate) identifier: Identifier,
    pub(crate) argument_list: Option<ArgumentList>,
}

impl Display for EnumVariantLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(".")?;
        Display::fmt(&self.identifier, f)?;
        if let Some(argument_list) = &self.argument_list {
            Display::fmt(argument_list, f)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct TupleLiteral {
    pub(crate) expressions: Vec<Expression>,
    pub(crate) span: Span,
}

impl Display for TupleLiteral {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        let len = self.expressions.len();
        for (index, expression) in self.expressions.iter().enumerate() {
            Display::fmt(expression, f)?;
            if index != len - 1 {
                f.write_str(", ")?;
            }
        }
        if len == 1 {
            f.write_str(",")?;
        }
        f.write_str(")")
    }
}

#[derive(Debug)]
pub(crate) struct ArrayLiteral {
    pub(crate) expressions: Vec<Expression>,
    pub(crate) span: Span,
}

impl Display for ArrayLiteral {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("[")?;
        let len = self.expressions.len();
        for (index, expression) in self.expressions.iter().enumerate() {
            Display::fmt(expression, f)?;
            if index != len - 1 {
                f.write_str(", ")?;
            }
        }
        f.write_str("]")
    }
}

#[derive(Debug)]
pub(crate) struct DictionaryLiteral {
    pub(crate) expressions: Vec<(Expression, Expression)>,
    pub(crate) span: Span,
}

impl Display for DictionaryLiteral {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("{")?;
        let len = self.expressions.len();
        for (index, (key, expression)) in self.expressions.iter().enumerate() {
            Display::fmt(key, f)?;
            f.write_str(": ")?;
            Display::fmt(expression, f)?;
            if index != len - 1 {
                f.write_str(", ")?;
            }
        }
        f.write_str("}")
    }
}
