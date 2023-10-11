use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::r#type::r#type::Type;

pub(crate) struct CallableVariant<'a> {
    pub(crate) generics_declarations: Vec<&'a GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<&'a ArgumentListDeclaration>,
    pub(crate) generics_constraints: Vec<&'a GenericsConstraint>,
    pub(crate) pipeline_input: Option<Type>,
    pub(crate) pipeline_output: Option<Type>,
}