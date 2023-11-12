use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::comment::Comment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct PipelineItemDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub define_availability: Availability,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub generics_declaration: Option<GenericsDeclaration>,
    pub argument_list_declaration: Option<ArgumentListDeclaration>,
    pub generics_constraint: Option<GenericsConstraint>,
    pub input_type: Option<TypeExpr>,
    pub output_type: Option<TypeExpr>,
    pub variants: Vec<PipelineItemDeclarationVariant>,
}

impl PipelineItemDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    pub fn has_variants(&self) -> bool {
        !self.variants.is_empty()
    }

    pub fn callable_variants(&self) -> Vec<CallableVariant> {
        if self.has_variants() {
            self.variants.iter().map(|v| CallableVariant {
                generics_declarations: if let Some(generics_declaration) = v.generics_declaration.as_ref() {
                    vec![generics_declaration]
                } else {
                    vec![]
                },
                argument_list_declaration: v.argument_list_declaration.as_ref(),
                generics_constraints: if let Some(generics_constraint) = v.generics_constraint.as_ref() {
                    vec![generics_constraint]
                } else {
                    vec![]
                },
                pipeline_input: Some(v.input_type.resolved().clone()),
                pipeline_output: Some(v.output_type.resolved().clone()),
            }).collect()
        } else {
            vec![CallableVariant {
                generics_declarations: if let Some(generics_declaration) = self.generics_declaration.as_ref() {
                    vec![generics_declaration]
                } else {
                    vec![]
                },
                argument_list_declaration: self.argument_list_declaration.as_ref(),
                generics_constraints: if let Some(generics_constraint) = self.generics_constraint.as_ref() {
                    vec![generics_constraint]
                } else {
                    vec![]
                },
                pipeline_input: self.input_type.as_ref().map(|t| t.resolved().clone()),
                pipeline_output: self.output_type.as_ref().map(|t| t.resolved().clone()),
            }]
        }
    }
}

#[derive(Debug)]
pub struct PipelineItemDeclarationVariant {
    pub span: Span,
    pub comment: Option<Comment>,
    pub generics_declaration: Option<GenericsDeclaration>,
    pub argument_list_declaration: Option<ArgumentListDeclaration>,
    pub generics_constraint: Option<GenericsConstraint>,
    pub input_type: TypeExpr,
    pub output_type: TypeExpr,
}
