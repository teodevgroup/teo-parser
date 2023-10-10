use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use crate::ast::arity::Arity;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::literals::EnumVariantLiteral;
use crate::ast::span::Span;
use crate::r#type::r#type::Type;

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
    FieldReference(EnumVariantLiteral),
}

impl TypeExprKind {

    pub(crate) fn span(&self) -> Span {
        match self {
            TypeExprKind::Expr(e) => e.span(),
            TypeExprKind::BinaryOp(b) => b.span,
            TypeExprKind::TypeItem(t) => t.span,
            TypeExprKind::TypeGroup(g) => g.span,
            TypeExprKind::TypeTuple(t) => t.span,
            TypeExprKind::FieldReference(e) => e.span,
        }
    }

    pub(crate) fn is_field_reference(&self) -> bool {
        self.as_field_reference().is_some()
    }

    pub(crate) fn as_field_reference(&self) -> Option<&EnumVariantLiteral> {
        match self {
            Self::FieldReference(e) => Some(e),
            _ => None,
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
            TypeExprKind::FieldReference(e) => Display::fmt(e, f)?,
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct TypeExpr {
    pub(crate) kind: TypeExprKind,
    pub(crate) resolved: RefCell<Option<Type>>,
}

impl TypeExpr {

    pub(crate) fn span(&self) -> Span {
        self.kind.span()
    }

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

#[derive(Debug)]
pub(crate) enum TypeShape {
    Any,
    Map(HashMap<String, TypeShape>),
    Type(Type),
    Undetermined,
}

impl TypeShape {

    pub(crate) fn is_any(&self) -> bool {
        match self {
            TypeShape::Any => true,
            _ => false,
        }
    }

    pub(crate) fn is_map(&self) -> bool {
        self.as_map().is_some()
    }

    pub(crate) fn as_map(&self) -> Option<&HashMap<String, TypeShape>> {
        match self {
            TypeShape::Map(m) => Some(m),
            _ => None,
        }
    }

    pub(crate) fn is_type(&self) -> bool {
        self.as_type().is_some()
    }

    pub(crate) fn as_type(&self) -> Option<&Type> {
        match self {
            TypeShape::Type(t) => Some(t),
            _ => None,
        }
    }
}
