use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;

#[derive(Debug)]
pub struct MiddlewareDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub identifier: Identifier,
    pub argument_list_declaration: Option<ArgumentListDeclaration>,
}

impl MiddlewareDeclaration {

    pub fn callable_variants(&self) -> Vec<CallableVariant> {
        vec![CallableVariant {
            generics_declarations: vec![],
            argument_list_declaration: self.argument_list_declaration.as_ref(),
            generics_constraints: vec![],
            pipeline_input: None,
            pipeline_output: None,
        }]
    }
}

impl Identifiable for MiddlewareDeclaration {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for MiddlewareDeclaration {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for MiddlewareDeclaration {
    fn define_availability(&self) -> Availability {
        Availability::default()
    }

    fn actual_availability(&self) -> Availability {
        Availability::default()
    }
}

impl InfoProvider for MiddlewareDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}
