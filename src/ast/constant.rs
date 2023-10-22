use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::availability::Availability;
use crate::ast::expression::{Expression, ExpressionResolved};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;
use crate::r#type::r#type::Type;

#[derive(Debug, Clone)]
pub(crate) struct ConstantResolved {
    pub(crate) expression_resolved: ExpressionResolved,
}

#[derive(Debug)]
pub struct Constant {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) identifier: Identifier,
    pub(crate) define_availability: Availability,
    pub(crate) type_expr: Option<TypeExpr>,
    pub(crate) expression: Expression,
    pub(crate) resolved: RefCell<Option<ConstantResolved>>,
}

impl Constant {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    pub(crate) fn resolve(&self, resolved: ConstantResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub(crate) fn resolved(&self) -> &ConstantResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub(crate) fn is_resolved(&self) -> bool {
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
