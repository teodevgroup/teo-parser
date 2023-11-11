use std::cell::RefCell;
use std::fmt::{Display, Formatter};
use crate::availability::Availability;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::resolved::Resolve;
use crate::value::TypeAndValue;

#[derive(Debug, Clone)]
pub struct ConstantResolved {
    pub expression_resolved: TypeAndValue,
}

#[derive(Debug)]
pub struct Constant {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub identifier: Identifier,
    pub type_expr: Option<TypeExpr>,
    pub expression: Expression,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
    pub resolved: RefCell<Option<ConstantResolved>>,
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
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for Constant {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for Constant {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for Constant {
    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Resolve<ConstantResolved> for Constant {
    fn resolved_ref_cell(&self) -> &RefCell<Option<ConstantResolved>> {
        &self.resolved
    }
}