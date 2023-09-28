use std::fmt::{Display, Formatter};
use crate::ast::expr::ExpressionKind;
use crate::ast::span::Span;

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Neg,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitXor,
    BitOr,
    BitNeg,
    NullishCoalescing,
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
        }
    }
}

#[derive(Debug)]
pub(crate) struct BinaryOp {
    pub(crate) span: Span,
    pub(crate) lhs: Box<ArithExpr>,
    pub(crate) op: Op,
    pub(crate) rhs: Box<ArithExpr>,
}

impl BinaryOp {

    pub(crate) fn span(&self) -> &Span {
        &self.span
    }
}

#[derive(Debug)]
pub(crate) enum ArithExpr {
    Expression(Box<ExpressionKind>),
    UnaryNeg(Box<ExpressionKind>),
    UnaryBitNeg(Box<ExpressionKind>),
    BinaryOp(BinaryOp),
}

impl ArithExpr {
    pub(crate) fn span(&self) -> &Span {
        match self {
            ArithExpr::Expression(e) => e.span(),
            ArithExpr::UnaryNeg(e) => e.span(),
            ArithExpr::UnaryBitNeg(e) => e.span(),
            ArithExpr::BinaryOp(b) => b.span(),
        }
    }
}

impl Display for ArithExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ArithExpr::UnaryNeg(e) => {
                f.write_str("-")?;
                Display::fmt(&e, f)
            },
            ArithExpr::UnaryBitNeg(e) => {
                f.write_str("~")?;
                Display::fmt(&e, f)
            },
            ArithExpr::Expression(e) => Display::fmt(&e, f),
            ArithExpr::BinaryOp(b) => {
                Display::fmt(&b.lhs, f)?;
                f.write_str(" ")?;
                Display::fmt(&b.op, f)?;
                f.write_str(" ")?;
                Display::fmt(&b.rhs, f)?;
                Ok(())
            }
        }
    }
}
