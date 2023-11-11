use std::fmt::{Display, Formatter};
use crate::ast::expression::Expression;
use crate::ast::span::Span;

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

#[derive(Debug)]
pub struct UnaryOperation {
    pub span: Span,
    pub op: Operator,
    pub rhs: Box<ArithExpr>,
}

#[derive(Debug)]
pub struct UnaryPostfixOperation {
    pub span: Span,
    pub op: Operator,
    pub lhs: Box<ArithExpr>,
}

#[derive(Debug)]
pub struct BinaryOperation {
    pub span: Span,
    pub lhs: Box<ArithExpr>,
    pub op: Operator,
    pub rhs: Box<ArithExpr>,
}

#[derive(Debug)]
pub enum ArithExpr {
    Expression(Box<Expression>),
    UnaryOperation(UnaryOperation),
    BinaryOperation(BinaryOperation),
    UnaryPostfixOperation(UnaryPostfixOperation),
}

impl ArithExpr {

    pub fn span(&self) -> Span {
        match self {
            ArithExpr::Expression(e) => e.span(),
            ArithExpr::UnaryOperation(u) => u.span,
            ArithExpr::BinaryOperation(b) => b.span,
            ArithExpr::UnaryPostfixOperation(u) => u.span,
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

impl Display for ArithExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ArithExpr::Expression(e) => Display::fmt(&e, f),
            ArithExpr::UnaryOperation(u) => {
                Display::fmt(&u.op, f)?;
                Display::fmt(&u.rhs, f)
            },
            ArithExpr::UnaryPostfixOperation(u) => {
                Display::fmt(&u.lhs, f)?;
                Display::fmt(&u.op, f)
            }
            ArithExpr::BinaryOperation(b) => {
                Display::fmt(&b.lhs, f)?;
                f.write_str(" ")?;
                Display::fmt(&b.op, f)?;
                f.write_str(" ")?;
                Display::fmt(&b.rhs, f)?;
                Ok(())
            },
        }
    }
}
