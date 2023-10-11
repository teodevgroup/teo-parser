use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};

pub(crate) struct CallableVariant<'a> {
    pub(crate) generics_declaration: Option<&'a GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<&'a ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<&'a GenericsConstraint>,
}