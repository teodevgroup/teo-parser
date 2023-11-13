use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use crate::ast::expression::Expression;
use crate::ast::span::Span;
use crate::{declare_container_node, node_child_fn};
use crate::ast::node::Node;
use crate::traits::identifiable::Identifiable;
use crate::traits::node_trait::NodeTrait;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operator {
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

impl Display for Operator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Operator::Neg => f.write_str("-"),
            Operator::Add => f.write_str("+"),
            Operator::Sub => f.write_str("-"),
            Operator::Mul => f.write_str("*"),
            Operator::Div => f.write_str("/"),
            Operator::Mod => f.write_str("%"),
            Operator::BitAnd => f.write_str("&"),
            Operator::BitXor => f.write_str("^"),
            Operator::BitOr => f.write_str("|"),
            Operator::BitNeg => f.write_str("~"),
            Operator::NullishCoalescing => f.write_str("??"),
            Operator::Not => f.write_str("!"),
            Operator::And => f.write_str("&&"),
            Operator::Or => f.write_str("||"),
            Operator::BitLS => f.write_str("<<"),
            Operator::BitRS => f.write_str(">>"),
            Operator::Gt => f.write_str(">"),
            Operator::Gte => f.write_str(">="),
            Operator::Lt => f.write_str("<"),
            Operator::Lte => f.write_str("<="),
            Operator::Eq => f.write_str("=="),
            Operator::Neq => f.write_str("!="),
            Operator::RangeOpen => f.write_str(".."),
            Operator::RangeClose => f.write_str("..."),
            Operator::ForceUnwrap => f.write_str("!"),
        }
    }
}

declare_container_node!(UnaryOperation, pub(crate) op: Operator, pub(crate) rhs: usize);

impl UnaryOperation {

    node_child_fn!(rhs, ArithExpr);
}

impl Display for UnaryOperation {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.op, f)?;
        Display::fmt(&self.rhs, f)
    }
}

declare_container_node!(UnaryPostfixOperation, pub(crate) op: Operator, pub(crate) lhs: usize);

impl UnaryPostfixOperation {

    node_child_fn!(lhs, ArithExpr);
}

impl Display for UnaryPostfixOperation {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.lhs, f)?;
        Display::fmt(&self.op, f)
    }
}

declare_container_node!(BinaryOperation, pub(crate) lhs: usize, pub(crate) op: Operator, pub(crate) rhs: usize);

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

impl Display for ArithExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ArithExpr::Expression(e) => Display::fmt(&e, f),
            ArithExpr::UnaryOperation(u) => Display::fmt(&u, f),
            ArithExpr::UnaryPostfixOperation(u) => Display::fmt(&u, f),
            ArithExpr::BinaryOperation(b) => Display::fmt(&b, f),
        }
    }
}
