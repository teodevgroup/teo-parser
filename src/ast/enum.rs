use std::cell::RefCell;
use std::sync::atomic::AtomicBool;
use teo_teon::value::Value;
use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::arith::ArithExpr;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::identifier::Identifier;
use crate::ast::info_provider::InfoProvider;
use crate::ast::literals::{NumericLiteral, StringLiteral};
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Enum {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub string_path: Vec<String>,
    pub(crate) define_availability: Availability,
    pub comment: Option<Comment>,
    pub(crate) decorators: Vec<Decorator>,
    pub interface: bool,
    pub option: bool,
    pub identifier: Identifier,
    pub members: Vec<EnumMember>,
    pub(crate) resolved: RefCell<Option<EnumResolved>>,
}

impl Enum {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn is_available(&self) -> bool {
        self.define_availability.contains(self.resolved().actual_availability)
    }

    pub(crate) fn resolve(&self, resolved: EnumResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub(crate) fn resolved(&self) -> &EnumResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub(crate) fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

impl InfoProvider for &Enum {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}

#[derive(Debug)]
pub(crate) struct EnumResolved {
    pub(crate) actual_availability: Availability,
}

#[derive(Debug)]
pub struct EnumMemberResolved {
    pub value: Value,
    pub(crate) actual_availability: Availability,
}

#[derive(Debug)]
pub struct EnumMember {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) define_availability: Availability,
    pub comment: Option<Comment>,
    pub(crate) decorators: Vec<Decorator>,
    pub identifier: Identifier,
    pub(crate) expression: Option<EnumMemberExpression>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) resolved: RefCell<Option<EnumMemberResolved>>,
}

impl EnumMember {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn is_available(&self) -> bool {
        self.define_availability.contains(self.resolved().actual_availability)
    }

    pub(crate) fn resolve(&self, resolved: EnumMemberResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &EnumMemberResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub(crate) fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

impl InfoProvider for &EnumMember {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(2).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}

#[derive(Debug)]
pub(crate) enum EnumMemberExpression {
    StringLiteral(StringLiteral),
    NumericLiteral(NumericLiteral),
    ArithExpr(ArithExpr),
}

impl EnumMemberExpression {

    pub(crate) fn is_string_literal(&self) -> bool {
        self.as_string_literal().is_some()
    }

    pub(crate) fn as_string_literal(&self) -> Option<&StringLiteral> {
        match self {
            Self::StringLiteral(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn is_arith_expr(&self) -> bool {
        self.as_arith_expr().is_some()
    }

    pub(crate) fn as_arith_expr(&self) -> Option<&ArithExpr> {
        match self {
            Self::ArithExpr(s) => Some(s),
            _ => None,
        }
    }

    pub(crate) fn span(&self) -> Span {
        match self {
            Self::StringLiteral(s) => s.span,
            Self::NumericLiteral(n) => n.span,
            Self::ArithExpr(a) => a.span(),
        }
    }
}
