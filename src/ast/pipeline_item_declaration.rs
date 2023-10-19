use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::comment::Comment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct PipelineItemDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) define_availability: Availability,
    pub(crate) comment: Option<Comment>,
    pub identifier: Identifier,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
    pub(crate) input_type: Option<TypeExpr>,
    pub(crate) output_type: Option<TypeExpr>,
    pub(crate) variants: Vec<PipelineItemDeclarationVariant>,
}

impl PipelineItemDeclaration {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    pub(crate) fn has_variants(&self) -> bool {
        !self.variants.is_empty()
    }

    pub(crate) fn callable_variants(&self) -> Vec<CallableVariant> {
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
pub(crate) struct PipelineItemDeclarationVariant {
    pub(crate) span: Span,
    pub(crate) comment: Option<Comment>,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
    pub(crate) input_type: TypeExpr,
    pub(crate) output_type: TypeExpr,
}
