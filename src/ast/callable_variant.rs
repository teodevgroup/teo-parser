use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::r#type::r#type::Type;

pub struct CallableVariant<'a> {
    pub generics_declarations: Vec<&'a GenericsDeclaration>,
    pub argument_list_declaration: Option<&'a ArgumentListDeclaration>,
    pub generics_constraints: Vec<&'a GenericsConstraint>,
    pub pipeline_input: Option<Type>,
    pub pipeline_output: Option<Type>,
}