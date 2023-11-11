use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::comment::Comment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;
use crate::ast::struct_declaration::StructDeclaration;

#[derive(Debug)]
pub struct FunctionDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub define_availability: Availability,
    pub comment: Option<Comment>,
    pub r#static: bool,
    pub identifier: Identifier,
    pub generics_declaration: Option<GenericsDeclaration>,
    pub argument_list_declaration: Option<ArgumentListDeclaration>,
    pub generics_constraint: Option<GenericsConstraint>,
    pub return_type: TypeExpr,
}

impl FunctionDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(2).rev().map(AsRef::as_ref).collect()
    }

    pub fn callable_variants<'a>(&'a self, struct_declaration: &'a StructDeclaration) -> Vec<CallableVariant<'a>> {
        let mut generics_declaration = vec![];
        let mut generics_constraint = vec![];
        if let Some(d) = struct_declaration.generics_declaration.as_ref() {
            generics_declaration.push(d);
        }
        if let Some(d) = struct_declaration.generics_constraint.as_ref() {
            generics_constraint.push(d);
        }
        if let Some(d) = self.generics_declaration.as_ref() {
            generics_declaration.push(d);
        }
        if let Some(d) = self.generics_constraint.as_ref() {
            generics_constraint.push(d);
        }
        vec![CallableVariant {
            generics_declarations: generics_declaration,
            argument_list_declaration: self.argument_list_declaration.as_ref(),
            generics_constraints: generics_constraint,
            pipeline_input: None,
            pipeline_output: None,
        }]
    }
}