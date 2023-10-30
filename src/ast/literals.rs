use std::fmt::{Display, Formatter};
use regex::Regex;
use teo_teon::value::Value;
use crate::ast::argument_list::ArgumentList;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct NumericLiteral {
    pub value: Value,
    pub span: Span,
}

impl Display for NumericLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.value, f)
    }
}


#[derive(Debug)]
pub struct StringLiteral {
    pub value: String,
    pub span: Span,
}

impl Display for StringLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.value)
    }
}

#[derive(Debug)]
pub struct RegexLiteral {
    pub value: Regex,
    pub span: Span,
}

impl Display for RegexLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("/")?;
        f.write_str(self.value.as_str())?;
        f.write_str("/")
    }
}

#[derive(Debug)]
pub struct BoolLiteral {
    pub value: bool,
    pub span: Span,
}

impl Display for BoolLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.value, f)
    }
}

#[derive(Debug, Default)]
pub struct NullLiteral {
    pub span: Span,
}

impl Display for NullLiteral {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("null")
    }
}

#[derive(Debug)]
pub struct EnumVariantLiteral {
    pub span: Span,
    pub identifier: Identifier,
    pub argument_list: Option<ArgumentList>,
}

impl EnumVariantLiteral {

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        Some(vec![self.identifier.name()])
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        Some(self.identifier.name())
    }
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
pub struct TupleLiteral {
    pub expressions: Vec<Expression>,
    pub span: Span,
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
pub struct ArrayLiteral {
    pub expressions: Vec<Expression>,
    pub span: Span,
}

impl ArrayLiteral {

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        let mut result = vec![];
        for expression in &self.expressions {
            if let Some(r) = expression.unwrap_enumerable_enum_member_string() {
                result.push(r);
            }
        }
        Some(result)
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        if self.expressions.len() < 1 {
            None
        } else {
            self.expressions.first().unwrap().unwrap_enumerable_enum_member_string()
        }
    }
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
pub struct DictionaryLiteral {
    pub expressions: Vec<(Expression, Expression)>,
    pub span: Span,
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
