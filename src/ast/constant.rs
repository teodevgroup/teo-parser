use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::ast::accessible::Accessible;
use crate::ast::expr::{Expression, ExpressionKind};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct ConstantResolved {
    pub(crate) accessible: Accessible,
}

#[derive(Debug)]
pub(crate) struct Constant {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) identifier: Identifier,
    pub(crate) type_expr: Option<TypeExpr>,
    pub(crate) expression: ExpressionKind,
    pub(crate) resolved: RefCell<Option<ConstantResolved>>,
}

impl Constant {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
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
