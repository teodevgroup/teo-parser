use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use crate::ast::arity::Arity;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::literals::EnumVariantLiteral;
use crate::ast::span::Span;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn};
use crate::ast::node::Node;
use crate::r#type::r#type::Type;
use crate::traits::identifiable::Identifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

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

declare_container_node!(TypeBinaryOperation,
    pub(crate) lhs: usize,
    pub op: TypeOperator,
    pub(crate) rhs: usize,
);

impl_container_node_defaults!(TypeBinaryOperation);

impl TypeBinaryOperation {

    node_child_fn!(lhs, TypeExpr);

    node_child_fn!(rhs, TypeExpr);
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

declare_container_node!(TypeGroup,
    pub(crate) type_expr: usize,
    pub arity: Arity,
    pub item_optional: bool,
    pub collection_optional: bool,
);

impl_container_node_defaults!(TypeGroup);

impl TypeGroup {

    node_child_fn!(type_expr, TypeExpr);
}

impl Display for TypeGroup {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        Display::fmt(self.type_expr(), f)?;
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

declare_container_node!(TypeTuple,
    pub(crate) items: Vec<usize>,
    pub arity: Arity,
    pub item_optional: bool,
    pub collection_optional: bool,
);

impl_container_node_defaults!(TypeTuple);

node_children_iter!(TypeTuple, TypeExpr, ItemsIter, items);

impl TypeTuple {

    node_children_iter_fn!(items, ItemsIter);
}


impl Display for TypeTuple {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("(")?;
        let len = self.items.len();
        for (index, kind) in self.items.iter().enumerate() {
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

declare_container_node!(TypeSubscript,
    pub(crate) container: usize,
    pub(crate) argument: usize,
    pub arity: Arity,
    pub item_optional: bool,
    pub collection_optional: bool,
);

impl_container_node_defaults!(TypeSubscript);

impl TypeSubscript {

    node_child_fn!(container, TypeExpr);

    node_child_fn!(argument, TypeExpr);
}

impl Display for TypeSubscript {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.container(), f)?;
        f.write_str("[")?;
        Display::fmt(self.argument(), f)?;
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

declare_container_node!(TypeItem,
    pub(crate) identifier_path: usize,
    pub(crate) generics: Vec<usize>,
    pub arity: Arity,
    pub item_optional: bool,
    pub collection_optional: bool,
);

impl_container_node_defaults!(TypeItem);

node_children_iter!(TypeItem, TypeExpr, GenericsIter, generics);

impl TypeItem {

    node_child_fn!(identifier_path, IdentifierPath);

    node_children_iter_fn!(generics, GenericsIter);
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

    pub fn as_dyn_node_trait(&self) -> &dyn NodeTrait {
        match self {
            TypeExprKind::Expr(n) => n,
            TypeExprKind::BinaryOp(n) => n,
            TypeExprKind::TypeItem(n) => n,
            TypeExprKind::TypeGroup(n) => n,
            TypeExprKind::TypeTuple(n) => n,
            TypeExprKind::TypeSubscript(n) => n,
            TypeExprKind::FieldName(n) => n,
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

impl Identifiable for TypeExprKind {

    fn path(&self) -> &Vec<usize> {
        self.as_dyn_node_trait().path()
    }
}

impl NodeTrait for TypeExprKind {
    fn span(&self) -> Span {
        self.as_dyn_node_trait().span()
    }

    fn children(&self) -> Option<&BTreeMap<usize, Node>> {
        self.as_dyn_node_trait().children()
    }
}

impl Display for TypeExprKind {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.as_dyn_node_trait(), f)
    }
}

#[derive(Debug)]
pub struct TypeExpr {
    pub kind: TypeExprKind,
    pub resolved: RefCell<Option<Type>>,
}

impl Identifiable for TypeExpr {
    fn path(&self) -> &Vec<usize> {
        self.kind.as_dyn_node_trait().path()
    }
}

impl NodeTrait for TypeExpr {
    fn span(&self) -> Span {
        self.kind.as_dyn_node_trait().span()
    }

    fn children(&self) -> Option<&BTreeMap<usize, Node>> {
        self.kind.as_dyn_node_trait().children()
    }
}

impl Resolve<Type> for TypeExpr {
    fn resolved_ref_cell(&self) -> &RefCell<Option<Type>> {
        &self.resolved
    }
}

impl Display for TypeExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.kind, f)
    }
}