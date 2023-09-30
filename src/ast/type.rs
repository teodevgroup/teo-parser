use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::arity::Arity;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::span::Span;

#[derive(Debug, Clone, Copy)]
pub enum TypeOp {
    BitOr,
}

impl Display for TypeOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeOp::BitOr => f.write_str("|"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TypeBinaryOp {
    pub(crate) span: Span,
    pub(crate) lhs: Box<TypeExprKind>,
    pub(crate) op: TypeOp,
    pub(crate) rhs: Box<TypeExprKind>,
}

impl Display for TypeBinaryOp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.lhs, f)?;
        f.write_str(" ")?;
        Display::fmt(&self.op, f)?;
        f.write_str(" ")?;
        Display::fmt(&self.rhs, f)?;
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum TypeExprKind {
    Expr(Box<TypeExprKind>),
    BinaryOp(TypeBinaryOp),
    TypeItem(TypeItem),
}

impl Display for TypeExprKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeExprKind::BinaryOp(b) => Display::fmt(b, f)?,
            TypeExprKind::Expr(e) => Display::fmt(e, f)?,
            TypeExprKind::TypeItem(t) => Display::fmt(t, f)?,
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum Type {
    Any,
    String,
    ObjectId,
    Date,
    DateTime,
    Bool,
    Int,
    Int64,
    Float32,
    Float,
    Decimal,
    Array(Box<Type>),
    Map(Box<Type>, Box<Type>),
    Enum(Vec<usize>),
    Model(Vec<usize>),
    Interface(Vec<usize>),
    Union(Vec<Type>),
    ScalarField(Vec<usize>),
    ScalarFieldAndCachedProperty(Vec<usize>),
    FieldType(Vec<usize>, String),
    Ignored,
}

impl Type {

    pub(crate) fn is_enum(&self) -> bool {
        match self {
            Type::Enum(_) => true,
            _ => false,
        }
    }

    /// is standard builtin types
    pub(crate) fn is_builtin(&self) -> bool {
        use Type::*;
        match self {
            String |
            ObjectId |
            Date |
            DateTime |
            Bool |
            Int |
            Int64 |
            Float32 |
            Float |
            Decimal |
            Array(_) |
            Map(_, _) => true,
            _ => false,
        }
    }

    pub(crate) fn is_model(&self) -> bool {
        match self {
            Type::Model(_) => true,
            _ => false,
        }
    }

    pub(crate) fn is_interface(&self) -> bool {
        match self {
            Type::Interface(_) => true,
            _ => false,
        }
    }

    pub(crate) fn model_path(&self) -> Option<&Vec<usize>> {
        match self {
            Type::Model(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn enum_path(&self) -> Option<&Vec<usize>> {
        match self {
            Type::Enum(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn interface_path(&self) -> Option<&Vec<usize>> {
        match self {
            Type::Interface(path) => Some(path),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct TypeExpr {
    pub(crate) kind: TypeExprKind,
    pub(crate) resolved: RefCell<Option<Type>>,
}

impl TypeExpr {

    pub(crate) fn resolve(&self, resolved: Type) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub(crate) fn resolved(&self) -> &Type {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }
}

impl Display for TypeExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.kind, f)
    }
}

#[derive(Debug)]
pub(crate) struct TypeItem {
    pub(crate) span: Span,
    pub(crate) identifier_path: IdentifierPath,
    pub(crate) generics: Vec<TypeExpr>,
    pub(crate) arity: Arity,
    pub(crate) item_required: bool,
    pub(crate) collection_required: bool,
}

impl Display for TypeItem {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.identifier_path, f)?;
        if self.generics.len() > 0 {
            f.write_str("<")?;
        }
        for (index, arg) in self.generics.iter().enumerate() {
            Display::fmt(arg, f)?;
            if index != self.generics.len() - 1 {
                f.write_str(", ")?;
            }
        }
        if self.generics.len() > 0 {
            f.write_str(">")?;
        }
        if !self.item_required {
            f.write_str("?")?;
        }
        if self.arity != Arity::Scalar {
            match self.arity {
                Arity::Array => f.write_str("[]")?,
                Arity::Dictionary => f.write_str("{}")?,
                _ => ()
            };
            if !self.collection_required {
                f.write_str("?")?;
            }
        }
        Ok(())
    }
}
