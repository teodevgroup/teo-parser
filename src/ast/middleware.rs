use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct MiddlewareDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub identifier: Identifier,
    pub argument_list_declaration: Option<ArgumentListDeclaration>,
}

impl MiddlewareDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

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
