use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::availability::Availability;
use crate::ast::expression::{Expression, ExpressionResolved};
use crate::ast::identifiable::Identifiable;
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;
use crate::r#type::r#type::Type;

#[derive(Debug, Clone)]
pub struct ConstantResolved {
    pub expression_resolved: ExpressionResolved,
}

#[derive(Debug)]
pub struct Constant {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub identifier: Identifier,
    pub define_availability: Availability,
    pub type_expr: Option<TypeExpr>,
    pub expression: Expression,
    pub resolved: RefCell<Option<ConstantResolved>>,
}

impl Constant {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    pub fn resolve(&self, resolved: ConstantResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &ConstantResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

impl Display for Constant {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("let ")?;
        Display::fmt(&self.identifier, f)?;
        f.write_str(" = ")?;
        Display::fmt(&self.expression, f)
    }
}

impl Identifiable for Constant {

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
        self.string_path.iter().map(|s| s.as_str()).collect()
    }
}