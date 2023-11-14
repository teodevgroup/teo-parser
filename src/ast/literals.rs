use std::fmt::{Display, Formatter};
use regex::Regex;
use teo_teon::value::Value;
use crate::ast::argument_list::ArgumentList;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::{declare_container_node, declare_node, impl_container_node_defaults, impl_node_defaults_with_write, node_child_fn, node_children_iter, node_children_iter_fn, node_children_pair_iter, node_optional_child_fn};

declare_node!(NumericLiteral, pub(crate) value: Value, pub(crate) display: String);

impl_node_defaults_with_write!(NumericLiteral, display);

declare_node!(StringLiteral, pub(crate) value: String, pub(crate) display: String);

impl_node_defaults_with_write!(StringLiteral, display);

declare_node!(RegexLiteral, pub(crate) value: Regex, pub(crate) display: String);

impl_node_defaults_with_write!(RegexLiteral, display);

declare_node!(BoolLiteral, pub(crate) value: bool);

impl_node_defaults_with_write!(BoolLiteral, value);

declare_node!(NullLiteral);

impl_node_defaults_with_write!(NullLiteral, "null");

declare_container_node!(EnumVariantLiteral,
    pub(crate) identifier: usize,
    pub(crate) argument_list: Option<usize>,
);

impl_container_node_defaults!(EnumVariantLiteral);

impl EnumVariantLiteral {

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(argument_list, ArgumentList);

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

declare_container_node!(TupleLiteral, pub(crate) expressions: Vec<usize>);

impl_container_node_defaults!(TupleLiteral);

node_children_iter!(TupleLiteral, Expression, TupleLiteralExpressionsIter, expressions);

impl TupleLiteral {

    node_children_iter_fn!(expressions, TupleLiteralExpressionsIter);
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

declare_container_node!(ArrayLiteral, pub(crate) expressions: Vec<usize>);

impl_container_node_defaults!(ArrayLiteral);

node_children_iter!(ArrayLiteral, Expression, ArrayLiteralExpressionsIter, expressions);

impl ArrayLiteral {

    node_children_iter_fn!(expressions, ArrayLiteralExpressionsIter);

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

declare_container_node!(DictionaryLiteral, pub(crate) expressions: Vec<(usize, usize)>);

impl_container_node_defaults!(DictionaryLiteral);

node_children_pair_iter!(DictionaryLiteral, Expression, DictionaryLiteralExpressionsIter, expressions);

impl DictionaryLiteral {

    node_children_iter_fn!(expressions, DictionaryLiteralExpressionsIter);
}

impl Display for DictionaryLiteral {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("{")?;
        let len = self.expressions.len();
        for (index, (key, expression)) in self.expressions().enumerate() {
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
