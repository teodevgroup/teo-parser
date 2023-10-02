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
pub(crate) struct TypeGroup {
    pub(crate) span: Span,
    pub(crate) kind: Box<TypeExprKind>,
    pub(crate) optional: bool,
}

impl Display for TypeGroup {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        Display::fmt(&self.kind, f)?;
        f.write_str(")")?;
        if self.optional {
            f.write_str("?")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct TypeTuple {
    pub(crate) span: Span,
    pub(crate) kinds: Vec<TypeExprKind>,
    pub(crate) optional: bool,
}

impl Display for TypeTuple {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let len = self.kinds.len();
        for (index, kind) in self.kinds.iter().enumerate() {
            Display::fmt(kind, f)?;
            if index != len - 1 {
                f.write_str(", ")?;
            } else if index == 0 {
                f.write_str(",")?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum TypeExprKind {
    Expr(Box<TypeExprKind>),
    BinaryOp(TypeBinaryOp),
    TypeItem(TypeItem),
    TypeGroup(TypeGroup),
    TypeTuple(TypeTuple),
}

impl TypeExprKind {

    pub(crate) fn span(&self) -> Span {
        match self {
            TypeExprKind::Expr(e) => e.span(),
            TypeExprKind::BinaryOp(b) => b.span,
            TypeExprKind::TypeItem(t) => t.span,
            TypeExprKind::TypeGroup(g) => g.span,
            TypeExprKind::TypeTuple(t) => t.span,
        }
    }
}

impl Display for TypeExprKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeExprKind::BinaryOp(b) => Display::fmt(b, f)?,
            TypeExprKind::Expr(e) => Display::fmt(e, f)?,
            TypeExprKind::TypeItem(i) => Display::fmt(i, f)?,
            TypeExprKind::TypeGroup(g) => Display::fmt(g, f)?,
            TypeExprKind::TypeTuple(t) => Display::fmt(t, f)?,
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) enum Type {
    Any,
    Null,
    Bool,
    Int,
    Int64,
    Float32,
    Float,
    Decimal,
    String,
    ObjectId,
    Date,
    DateTime,
    File,
    Array(Box<Type>),
    Dictionary(Box<Type>, Box<Type>),
    Tuple(Vec<Type>),
    Range(Box<Type>),
    Union(Vec<Type>),
    Ignored,
    Enum(Vec<usize>),
    Model(Vec<usize>),
    Interface(Vec<usize>),
    ModelScalarField(Vec<usize>),
    ModelScalarFieldAndCachedProperty(Vec<usize>),
    FieldType(Vec<usize>, String),
    GenericItem(String),
    Optional(Box<Type>),
    Unresolved,
}

impl Type {

    pub(crate) fn is_optional(&self) -> bool {
        match self {
            Type::Optional(_) => true,
            _ => false,
        }
    }

    pub(crate) fn is_int_32_or_64(&self) -> bool {
        match self {
            Type::Int | Type::Int64 => true,
            _ => false,
        }
    }

    pub(crate) fn is_float_32_or_64(&self) -> bool {
        match self {
            Type::Float32 | Type::Float => true,
            _ => false,
        }
    }

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
            Null |
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
            File |
            Array(_) |
            Dictionary(_, _) |
            Tuple(_) => true,
            Optional(inner) => inner.is_builtin(),
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
    pub(crate) generics: Vec<TypeExprKind>,
    pub(crate) arity: Arity,
    pub(crate) item_optional: bool,
    pub(crate) collection_optional: bool,
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
        if self.item_optional {
            f.write_str("?")?;
        }
        if self.arity != Arity::Scalar {
            match self.arity {
                Arity::Array => f.write_str("[]")?,
                Arity::Dictionary => f.write_str("{}")?,
                _ => ()
            };
            if self.collection_optional {
                f.write_str("?")?;
            }
        }
        Ok(())
    }
}
