use regex::Regex;
use teo_teon::value::Value;
use crate::ast::argument_list::ArgumentList;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::{declare_container_node, declare_node, impl_container_node_defaults, impl_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::ast::named_expression::NamedExpression;
use crate::format::Writer;
use crate::traits::write::Write;

declare_node!(NumericLiteral, pub(crate) value: Value, pub(crate) display: String);

impl_node_defaults!(NumericLiteral);

impl Write for NumericLiteral {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_content(self, self.display.as_str());
    }
}

declare_node!(StringLiteral, pub(crate) value: String, pub(crate) display: String);

impl_node_defaults!(StringLiteral);

impl Write for StringLiteral {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_content(self, self.display.as_str());
    }
}

declare_node!(RegexLiteral, pub(crate) value: Regex, pub(crate) display: String);

impl_node_defaults!(RegexLiteral);

impl Write for RegexLiteral {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_content(self, self.display.as_str());
    }
}

declare_node!(BoolLiteral, pub(crate) value: bool);

impl_node_defaults!(BoolLiteral);

impl Write for BoolLiteral {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_content(self, if self.value { "true" } else { "false" });
    }
}

declare_node!(NullLiteral);

impl_node_defaults!(NullLiteral);

impl Write for NullLiteral {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_content(self, "null")
    }
}

declare_container_node!(EnumVariantLiteral,
    pub(crate) identifier: usize,
    pub(crate) argument_list: Option<usize>,
);

impl_container_node_defaults!(EnumVariantLiteral);

impl EnumVariantLiteral {

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(argument_list, ArgumentList);

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        Some(vec![self.identifier().name()])
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        Some(self.identifier().name())
    }
}

impl Write for EnumVariantLiteral {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }
}

declare_container_node!(TupleLiteral, pub(crate) expressions: Vec<usize>);

impl_container_node_defaults!(TupleLiteral);

node_children_iter!(TupleLiteral, Expression, TupleLiteralExpressionsIter, expressions);

impl TupleLiteral {

    node_children_iter_fn!(expressions, TupleLiteralExpressionsIter);
}

impl Write for TupleLiteral {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }
}

declare_container_node!(ArrayLiteral, pub(crate) expressions: Vec<usize>);

impl_container_node_defaults!(ArrayLiteral);

node_children_iter!(ArrayLiteral, Expression, ArrayLiteralExpressionsIter, expressions);

impl ArrayLiteral {

    node_children_iter_fn!(expressions, ArrayLiteralExpressionsIter);

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        let mut result = vec![];
        for expression in self.expressions() {
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
            self.expressions().next().unwrap().unwrap_enumerable_enum_member_string()
        }
    }
}

impl Write for ArrayLiteral {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }
}

declare_container_node!(DictionaryLiteral,
    pub(crate) expressions: Vec<usize>,
    pub(crate) namespace_path: Vec<usize>,
    pub(crate) is_config_field: bool,
);

impl_container_node_defaults!(DictionaryLiteral);

node_children_iter!(DictionaryLiteral, NamedExpression, DictionaryLiteralExpressionsIter, expressions);

impl DictionaryLiteral {

    node_children_iter_fn!(expressions, DictionaryLiteralExpressionsIter);
}

impl Write for DictionaryLiteral {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values())
    }
}
