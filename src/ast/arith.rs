use std::fmt::{Display, Formatter};
use crate::ast::expression::Expression;
use crate::ast::span::Span;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Op {
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

impl Display for Op {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Op::Neg => f.write_str("-"),
            Op::Add => f.write_str("+"),
            Op::Sub => f.write_str("-"),
            Op::Mul => f.write_str("*"),
            Op::Div => f.write_str("/"),
            Op::Mod => f.write_str("%"),
            Op::BitAnd => f.write_str("&"),
            Op::BitXor => f.write_str("^"),
            Op::BitOr => f.write_str("|"),
            Op::BitNeg => f.write_str("~"),
            Op::NullishCoalescing => f.write_str("??"),
            Op::Not => f.write_str("!"),
            Op::And => f.write_str("&&"),
            Op::Or => f.write_str("||"),
            Op::BitLS => f.write_str("<<"),
            Op::BitRS => f.write_str(">>"),
            Op::Gt => f.write_str(">"),
            Op::Gte => f.write_str(">="),
            Op::Lt => f.write_str("<"),
            Op::Lte => f.write_str("<="),
            Op::Eq => f.write_str("=="),
            Op::Neq => f.write_str("!="),
            Op::RangeOpen => f.write_str(".."),
            Op::RangeClose => f.write_str("..."),
            Op::ForceUnwrap => f.write_str("!"),
        }
    }
}

#[derive(Debug)]
pub struct UnaryOp {
    pub span: Span,
    pub op: Op,
    pub rhs: Box<ArithExpr>,
}

#[derive(Debug)]
pub struct UnaryPostfixOp {
    pub span: Span,
    pub op: Op,
    pub lhs: Box<ArithExpr>,
}

#[derive(Debug)]
pub struct BinaryOp {
    pub span: Span,
    pub lhs: Box<ArithExpr>,
    pub op: Op,
    pub rhs: Box<ArithExpr>,
}

#[derive(Debug)]
pub enum ArithExpr {
    Expression(Box<Expression>),
    UnaryOp(UnaryOp),
    BinaryOp(BinaryOp),
    UnaryPostfixOp(UnaryPostfixOp),
}

impl ArithExpr {

    pub fn span(&self) -> Span {
        match self {
            ArithExpr::Expression(e) => e.span(),
            ArithExpr::UnaryOp(u) => u.span,
            ArithExpr::BinaryOp(b) => b.span,
            ArithExpr::UnaryPostfixOp(u) => u.span,
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
            ArithExpr::UnaryOp(u) => {
                Display::fmt(&u.op, f)?;
                Display::fmt(&u.rhs, f)
            },
            ArithExpr::UnaryPostfixOp(u) => {
                Display::fmt(&u.lhs, f)?;
                Display::fmt(&u.op, f)
            }
            ArithExpr::BinaryOp(b) => {
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
