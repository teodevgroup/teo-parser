use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use crate::ast::expression::Expression;
use crate::ast::span::Span;
use crate::{declare_container_node, node_child_fn};
use crate::ast::node::Node;
use crate::format::Writer;
use crate::traits::identifiable::Identifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::write::Write;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ArithExprOperator {
    Neg,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Not,
    And,
    Or,
    BitAnd,
    BitXor,
    BitOr,
    BitNeg,
    BitLS,
    BitRS,
    NullishCoalescing,
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Neq,
    RangeOpen,
    RangeClose,
    ForceUnwrap,
}

declare_container_node!(UnaryOperation, pub(crate) op: ArithExprOperator, pub(crate) rhs: usize);

impl UnaryOperation {

    node_child_fn!(rhs, ArithExpr);
}

impl Display for UnaryOperation {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.op, f)?;
        Display::fmt(&self.rhs, f)
    }
}

declare_container_node!(UnaryPostfixOperation, pub(crate) op: ArithExprOperator, pub(crate) lhs: usize);

impl UnaryPostfixOperation {

    node_child_fn!(lhs, ArithExpr);
}

impl Display for UnaryPostfixOperation {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.lhs, f)?;
        Display::fmt(&self.op, f)
    }
}

declare_container_node!(BinaryOperation, pub(crate) lhs: usize, pub(crate) op: ArithExprOperator, pub(crate) rhs: usize);

impl BinaryOperation {

    node_child_fn!(lhs, ArithExpr);
    node_child_fn!(rhs, ArithExpr);
}

impl Display for BinaryOperation {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.lhs, f)?;
        f.write_str(" ")?;
        Display::fmt(&self.op, f)?;
        f.write_str(" ")?;
        Display::fmt(&self.rhs, f)
    }
}

#[derive(Debug)]
pub enum ArithExpr {
    Expression(Box<Expression>),
    UnaryOperation(UnaryOperation),
    BinaryOperation(BinaryOperation),
    UnaryPostfixOperation(UnaryPostfixOperation),
}

impl ArithExpr {

    pub fn as_dyn_node_trait(&self) -> &dyn NodeTrait {
        match self {
            ArithExpr::Expression(n) => n.as_ref(),
            ArithExpr::UnaryOperation(n) => n,
            ArithExpr::BinaryOperation(n) => n,
            ArithExpr::UnaryPostfixOperation(n) => n,
        }
    }

    pub fn unwrap_enumerable_enum_member_strings(&self) -> Option<Vec<&str>> {
        match self {
            ArithExpr::Expression(e) => e.unwrap_enumerable_enum_member_strings(),
            _ => None,
        }
    }

    pub fn unwrap_enumerable_enum_member_string(&self) -> Option<&str> {
        match self {
            ArithExpr::Expression(e) => e.unwrap_enumerable_enum_member_string(),
            _ => None,
        }
    }
}

impl Identifiable for ArithExpr {
    fn path(&self) -> &Vec<usize> {
        self.as_dyn_node_trait().path()
    }
}

impl NodeTrait for ArithExpr {
    fn span(&self) -> Span {
        self.as_dyn_node_trait().span()
    }

    fn children(&self) -> Option<&BTreeMap<usize, Node>> {
        self.as_dyn_node_trait().children()
    }
}

impl Write for ArithExpr {
    fn write(&self, writer: &mut Writer) {
        self.as_dyn_node_trait().write(writer);
    }

    fn write_output_with_default_writer(&self) -> String {
        self.as_dyn_node_trait().write_output_with_default_writer()
    }

    fn prefer_whitespace_before(&self) -> bool {
        self.as_dyn_node_trait().prefer_whitespace_before()
    }

    fn prefer_whitespace_after(&self) -> bool {
        self.as_dyn_node_trait().prefer_whitespace_after()
    }

    fn prefer_always_no_whitespace_before(&self) -> bool {
        self.as_dyn_node_trait().prefer_always_no_whitespace_before()
    }

    fn always_start_on_new_line(&self) -> bool {
        self.as_dyn_node_trait().always_start_on_new_line()
    }

    fn always_end_on_new_line(&self) -> bool {
        self.as_dyn_node_trait().always_end_on_new_line()
    }

    fn is_block_start(&self) -> bool {
        self.as_dyn_node_trait().is_block_start()
    }

    fn is_block_end(&self) -> bool {
        self.as_dyn_node_trait().is_block_end()
    }

    fn is_block_element_delimiter(&self) -> bool {
        self.as_dyn_node_trait().is_block_element_delimiter()
    }

    fn is_block_level_element(&self) -> bool {
        self.as_dyn_node_trait().is_block_level_element()
    }

    fn wrap(&self, content: &str, available_length: usize) -> String {
        self.as_dyn_node_trait().wrap(content, available_length)
    }
}

impl Display for ArithExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.as_dyn_node_trait(), f)
    }
}