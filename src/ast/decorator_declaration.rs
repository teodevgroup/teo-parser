use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::comment::Comment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::reference::ReferenceType;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct DecoratorDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) exclusive: bool,
    pub(crate) unique: bool,
    pub(crate) decorator_class: ReferenceType,
    pub(crate) identifier: Identifier,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
    pub(crate) variants: Vec<DecoratorDeclarationVariant>,
}

impl DecoratorDeclaration {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub(crate) fn has_variants(&self) -> bool {
        !self.variants.is_empty()
    }

    pub(crate) fn callable_variants(&self) -> Vec<CallableVariant> {
        if self.has_variants() {
            self.variants.iter().map(|v| CallableVariant {
                generics_declaration: v.generics_declaration.as_ref(),
                argument_list_declaration: v.argument_list_declaration.as_ref(),
                generics_constraint: v.generics_constraint.as_ref(),
                pipeline_input: None,
                pipeline_output: None,
            }).collect()
        } else {
            vec![CallableVariant {
                generics_declaration: self.generics_declaration.as_ref(),
                argument_list_declaration: self.argument_list_declaration.as_ref(),
                generics_constraint: self.generics_constraint.as_ref(),
                pipeline_input: None,
                pipeline_output: None,
            }]
        }
    }
}

#[derive(Debug)]
pub(crate) struct DecoratorDeclarationVariant {
    pub(crate) span: Span,
    pub(crate) comment: Option<Comment>,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
}
