use std::cell::RefCell;
use teo_teon::value::Value;
use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::arith_expr::ArithExpr;
use crate::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::comment::Comment;
use crate::ast::decorator::Decorator;
use crate::ast::identifier::Identifier;
use crate::ast::literals::{NumericLiteral, StringLiteral};
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::resolved::Resolve;

#[derive(Debug)]
pub struct Enum {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub decorators: Vec<Decorator>,
    pub interface: bool,
    pub option: bool,
    pub identifier: Identifier,
    pub members: Vec<EnumMember>,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
}

impl Identifiable for Enum {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for Enum {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for Enum {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for Enum {
    fn namespace_skip(&self) -> usize {
        1
    }
}

#[derive(Debug)]
pub struct EnumMemberResolved {
    pub value: Value,
}

#[derive(Debug)]
pub struct EnumMember {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub decorators: Vec<Decorator>,
    pub identifier: Identifier,
    pub expression: Option<EnumMemberExpression>,
    pub argument_list_declaration: Option<ArgumentListDeclaration>,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
    pub resolved: RefCell<Option<EnumMemberResolved>>,
}

impl EnumMember {

    pub fn callable_variants(&self) -> Vec<CallableVariant> {
        self.argument_list_declaration.iter().map(|a| CallableVariant {
            generics_declarations: vec![],
            argument_list_declaration: Some(a),
            generics_constraints: vec![],
            pipeline_input: None,
            pipeline_output: None,
        }).collect()
    }
}

impl Identifiable for EnumMember {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for EnumMember {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for EnumMember {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for EnumMember {
    fn namespace_skip(&self) -> usize {
        2
    }
}

impl Resolve<EnumMemberResolved> for EnumMember {

    fn resolved_ref_cell(&self) -> &RefCell<Option<EnumMemberResolved>> {
        &self.resolved
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
