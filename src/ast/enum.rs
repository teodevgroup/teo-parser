use std::cell::RefCell;
use std::sync::atomic::AtomicBool;
use teo_teon::value::Value;
use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::arith::ArithExpr;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::identifiable::Identifiable;
use crate::ast::identifier::Identifier;
use crate::ast::info_provider::InfoProvider;
use crate::ast::literals::{NumericLiteral, StringLiteral};
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Enum {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub define_availability: Availability,
    pub comment: Option<Comment>,
    pub decorators: Vec<Decorator>,
    pub interface: bool,
    pub option: bool,
    pub identifier: Identifier,
    pub members: Vec<EnumMember>,
    pub resolved: RefCell<Option<EnumResolved>>,
}

impl Enum {

    pub fn is_available(&self) -> bool {
        self.define_availability.contains(self.resolved().actual_availability)
    }

    pub fn resolve(&self, resolved: EnumResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &EnumResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

impl Identifiable for Enum {

    fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    fn path(&self) -> &Vec<usize> {
        &self.path
    }

    fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }
}

impl InfoProvider for Enum {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}

#[derive(Debug)]
pub struct EnumResolved {
    pub actual_availability: Availability,
}

#[derive(Debug)]
pub struct EnumMemberResolved {
    pub value: Value,
    pub actual_availability: Availability,
}

#[derive(Debug)]
pub struct EnumMember {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub define_availability: Availability,
    pub comment: Option<Comment>,
    pub decorators: Vec<Decorator>,
    pub identifier: Identifier,
    pub expression: Option<EnumMemberExpression>,
    pub argument_list_declaration: Option<ArgumentListDeclaration>,
    pub resolved: RefCell<Option<EnumMemberResolved>>,
}

impl EnumMember {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn is_available(&self) -> bool {
        self.define_availability.contains(self.resolved().actual_availability)
    }

    pub fn resolve(&self, resolved: EnumMemberResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &EnumMemberResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

impl Identifiable for EnumMember {

    fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    fn path(&self) -> &Vec<usize> {
        &self.path
    }

    fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }
}

impl InfoProvider for EnumMember {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(2).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}

#[derive(Debug)]
pub enum EnumMemberExpression {
    StringLiteral(StringLiteral),
    NumericLiteral(NumericLiteral),
    ArithExpr(ArithExpr),
}

impl EnumMemberExpression {

    pub fn is_string_literal(&self) -> bool {
        self.as_string_literal().is_some()
    }

    pub fn as_string_literal(&self) -> Option<&StringLiteral> {
        match self {
            Self::StringLiteral(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_arith_expr(&self) -> bool {
        self.as_arith_expr().is_some()
    }

    pub fn as_arith_expr(&self) -> Option<&ArithExpr> {
        match self {
            Self::ArithExpr(s) => Some(s),
            _ => None,
        }
    }

    pub fn span(&self) -> Span {
        match self {
            Self::StringLiteral(s) => s.span,
            Self::NumericLiteral(n) => n.span,
            Self::ArithExpr(a) => a.span(),
        }
    }
}
