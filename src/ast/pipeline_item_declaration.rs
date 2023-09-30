use crate::ast::argument_declaration::ArgumentListDeclaration;
use crate::ast::comment::Comment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::r#type::TypeExpr;
use crate::ast::span::Span;

#[derive(Debug)]
pub(crate) struct PipelineItemDeclaration {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) comment: Option<Comment>,
    pub(crate) identifier: Identifier,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
    pub(crate) input_type: Option<TypeExpr>,
    pub(crate) output_type: Option<TypeExpr>,
    pub(crate) variants: Vec<PipelineItemVariant>,
}

impl PipelineItemDeclaration {

    pub(crate) fn has_variants(&self) -> bool {
        !self.variants.is_empty()
    }
}

#[derive(Debug)]
pub(crate) struct PipelineItemVariant {
    pub(crate) span: Span,
    pub(crate) comment: Option<Comment>,
    pub(crate) generics_declaration: Option<GenericsDeclaration>,
    pub(crate) argument_list_declaration: Option<ArgumentListDeclaration>,
    pub(crate) generics_constraint: Option<GenericsConstraint>,
    pub(crate) input_type: TypeExpr,
    pub(crate) output_type: TypeExpr,
}
