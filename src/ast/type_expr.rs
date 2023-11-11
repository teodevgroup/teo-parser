use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::arity::Arity;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::literals::EnumVariantLiteral;
use crate::ast::span::Span;
use crate::r#type::r#type::Type;

#[derive(Debug, Clone, Copy)]
pub enum TypeOperator {
    BitOr,
}

impl Display for TypeOperator {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeOperator::BitOr => f.write_str("|"),
        }
    }
}

#[derive(Debug)]
pub struct TypeBinaryOperation {
    pub span: Span,
    pub lhs: Box<TypeExprKind>,
    pub op: TypeOperator,
    pub rhs: Box<TypeExprKind>,
}

impl Display for TypeBinaryOperation {

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
pub struct TypeGroup {
    pub span: Span,
    pub kind: Box<TypeExprKind>,
    pub arity: Arity,
    pub item_optional: bool,
    pub collection_optional: bool,
}

impl Display for TypeGroup {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        Display::fmt(&self.kind, f)?;
        f.write_str(")")?;
        if self.item_optional {
            f.write_str("?")?;
        }
        if !self.arity.is_scalar() {
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
pub struct TypeTuple {
    pub span: Span,
    pub kinds: Vec<TypeExprKind>,
    pub arity: Arity,
    pub item_optional: bool,
    pub collection_optional: bool,
}

impl Display for TypeTuple {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        let len = self.kinds.len();
        for (index, kind) in self.kinds.iter().enumerate() {
            Display::fmt(kind, f)?;
            if index != len - 1 {
                f.write_str(", ")?;
            } else if index == 0 {
                f.write_str(",")?;
            }
        }
        f.write_str(")")?;
        if self.item_optional {
            f.write_str("?")?;
        }
        if !self.arity.is_scalar() {
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
pub struct TypeSubscript {
    pub span: Span,
    pub type_item: TypeItem,
    pub type_expr: Box<TypeExprKind>,
    pub arity: Arity,
    pub item_optional: bool,
    pub collection_optional: bool,
}

impl Display for TypeSubscript {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.type_item, f)?;
        f.write_str("[")?;
        Display::fmt(&self.type_expr, f)?;
        f.write_str("]")?;
        if self.item_optional {
            f.write_str("?")?;
        }
        if !self.arity.is_scalar() {
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
pub enum TypeExprKind {
    Expr(Box<TypeExprKind>),
    BinaryOp(TypeBinaryOperation),
    TypeItem(TypeItem),
    TypeGroup(TypeGroup),
    TypeTuple(TypeTuple),
    TypeSubscript(TypeSubscript),
    FieldName(EnumVariantLiteral),
}

impl TypeExprKind {

    pub fn span(&self) -> Span {
        match self {
            TypeExprKind::Expr(e) => e.span(),
            TypeExprKind::BinaryOp(b) => b.span,
            TypeExprKind::TypeItem(t) => t.span,
            TypeExprKind::TypeGroup(g) => g.span,
            TypeExprKind::TypeTuple(t) => t.span,
            TypeExprKind::TypeSubscript(s) => s.span,
            TypeExprKind::FieldName(e) => e.span,
        }
    }

    pub fn is_field_reference(&self) -> bool {
        self.as_field_reference().is_some()
    }

    pub fn as_field_reference(&self) -> Option<&EnumVariantLiteral> {
        match self {
            Self::FieldName(e) => Some(e),
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
            TypeExprKind::TypeSubscript(s) => Display::fmt(s, f)?,
            TypeExprKind::FieldName(e) => Display::fmt(e, f)?,
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct TypeExpr {
    pub kind: TypeExprKind,
    pub resolved: RefCell<Option<Type>>,
}

impl TypeExpr {

    pub fn span(&self) -> Span {
        self.kind.span()
    }

    pub fn resolve(&self, resolved: Type) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &Type {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }
}

impl Display for TypeExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.kind, f)
    }
}

#[derive(Debug)]
pub struct TypeItem {
    pub span: Span,
    pub identifier_path: IdentifierPath,
    pub generics: Vec<TypeExprKind>,
    pub arity: Arity,
    pub item_optional: bool,
    pub collection_optional: bool,
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
