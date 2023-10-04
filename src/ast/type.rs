use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use itertools::Itertools;
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

#[derive(Debug, Clone)]
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
    Interface(Vec<usize>, Vec<Type>),
    ModelScalarField(Vec<usize>),
    ModelScalarFieldAndCachedProperty(Vec<usize>),
    FieldType(Vec<usize>, String),
    GenericItem(String),
    Optional(Box<Type>),
    Keyword(TypeKeyword),
    Object(Box<Type>),
    Unresolved,
}

impl Type {

    pub(crate) fn contains<F>(&self, f: F) -> bool where F: Fn(&Self) -> bool {
        if self.is_container() {
            match self {
                Type::Array(t) => t.as_ref().contains(f),
                Type::Dictionary(k, v) => {
                    let matcher = |f: &dyn Fn(&Self) -> bool, t: &Type | { f(t) };
                    matcher(&f, k.as_ref()) || matcher(&f, v.as_ref())
                },
                Type::Tuple(t) => t.iter().find(|t| f(*t)).is_some(),
                Type::Range(t) => t.as_ref().contains(f),
                Type::Union(u) => u.iter().find(|t| f(*t)).is_some(),
                Type::Optional(o) => o.as_ref().contains(f),
                _ => false,
            }
        } else {
            f(self)
        }
    }

    pub(crate) fn is_container(&self) -> bool {
        match self {
            Type::Any => false,
            Type::Null => false,
            Type::Bool => false,
            Type::Int => false,
            Type::Int64 => false,
            Type::Float32 => false,
            Type::Float => false,
            Type::Decimal => false,
            Type::String => false,
            Type::ObjectId => false,
            Type::Date => false,
            Type::DateTime => false,
            Type::File => false,
            Type::Array(_) => true,
            Type::Dictionary(_, _) => true,
            Type::Tuple(_) => true,
            Type::Range(_) => true,
            Type::Union(_) => true,
            Type::Ignored => false,
            Type::Enum(_) => false,
            Type::Model(_) => false,
            Type::Interface(_, _) => false,
            Type::ModelScalarField(_) => false,
            Type::ModelScalarFieldAndCachedProperty(_) => false,
            Type::FieldType(_, _) => false,
            Type::GenericItem(_) => false,
            Type::Optional(_) => true,
            Type::Unresolved => false,
            Type::Object(_) => false,
            Type::Keyword(_) => false,
        }
    }

    pub(crate) fn replace_generics(&self, map: &HashMap<String, &Type>) -> Self {
        match self {
            Type::Any => self.clone(),
            Type::Null => self.clone(),
            Type::Bool => self.clone(),
            Type::Int => self.clone(),
            Type::Int64 => self.clone(),
            Type::Float32 => self.clone(),
            Type::Float => self.clone(),
            Type::Decimal => self.clone(),
            Type::String => self.clone(),
            Type::ObjectId => self.clone(),
            Type::Date => self.clone(),
            Type::DateTime => self.clone(),
            Type::File => self.clone(),
            Type::Array(inner) => Type::Array(Box::new(inner.replace_generics(map))),
            Type::Dictionary(k, v) => Type::Dictionary(Box::new(k.replace_generics(map)), Box::new(v.replace_generics(map))),
            Type::Tuple(inner) => Type::Tuple(inner.iter().map(|t| t.replace_generics(map)).collect()),
            Type::Range(inner) => Type::Range(Box::new(inner.replace_generics(map))),
            Type::Union(inner) => Type::Union(inner.iter().map(|t| t.replace_generics(map)).collect()),
            Type::Ignored => self.clone(),
            Type::Enum(_) => self.clone(),
            Type::Model(_) => self.clone(),
            Type::Interface(path, generics) => Type::Interface(path.clone(), generics.iter().map(|t| t.replace_generics(map)).collect()),
            Type::ModelScalarField(_) => self.clone(),
            Type::ModelScalarFieldAndCachedProperty(_) => self.clone(),
            Type::FieldType(_, _) => self.clone(),
            Type::GenericItem(name) => map.get(name).cloned().unwrap_or(&Type::Unresolved).clone(),
            Type::Optional(inner) => Type::Optional(Box::new(inner.replace_generics(map))),
            Type::Unresolved => self.clone(),
            Type::Keyword(_) => self.clone(),
            Type::Object(_) => self.clone(),
        }
    }

    pub(crate) fn is_keyword(&self) -> bool {
        self.as_keyword().is_some()
    }

    pub(crate) fn as_keyword(&self) -> Option<&TypeKeyword> {
        match self {
            Self::Keyword(k) => Some(k),
            _ => None,
        }
    }

    pub(crate) fn is_optional(&self) -> bool {
        match self {
            Type::Optional(_) => true,
            _ => false,
        }
    }

    pub(crate) fn is_any(&self) -> bool {
        match self {
            Type::Any => true,
            _ => false,
        }
    }

    pub(crate) fn is_ignored(&self) -> bool {
        match self {
            Type::Ignored => true,
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

    pub(crate) fn is_file(&self) -> bool {
        match self {
            Type::File => true,
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
            Type::Interface(_, __) => true,
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
            Type::Interface(path, _) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn interface_generics(&self) -> Option<&Vec<Type>> {
        match self {
            Type::Interface(_, generics) => Some(generics),
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

    pub(crate) fn span(&self) -> Span {
        match &self.kind {
            TypeExprKind::Expr(e) => e.span(),
            TypeExprKind::BinaryOp(b) => b.span,
            TypeExprKind::TypeItem(i) => i.span,
            TypeExprKind::TypeGroup(g) => g.span,
            TypeExprKind::TypeTuple(t) => t.span,
        }
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

#[derive(Debug, Copy, Clone)]
pub(crate) enum TypeKeyword {
    SelfIdentifier,
    FieldType,
}

impl TypeKeyword {

    pub(crate) fn is_self(&self) -> bool {
        match self {
            TypeKeyword::SelfIdentifier => true,
            _ => false,
        }
    }

    pub(crate) fn is_field_type(&self) -> bool {
        match self {
            TypeKeyword::FieldType => true,
            _ => false,
        }
    }
}