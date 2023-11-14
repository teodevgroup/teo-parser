use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::doc_comment::DocComment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};

declare_container_node!(PipelineItemDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) generics_declaration: Option<usize>,
    pub(crate) argument_list_declaration: Option<usize>,
    pub(crate) generics_constraint: Option<usize>,
    pub(crate) input_type: Option<usize>,
    pub(crate) output_type: Option<usize>,
    pub(crate) variants: Vec<usize>,
);

impl_container_node_defaults!(PipelineItemDeclaration, named, availability);

node_children_iter!(PipelineItemDeclaration, PipelineItemDeclarationVariant, VariantsIter, variants);

impl PipelineItemDeclaration {

    node_optional_child_fn!(comment, DocComment);
    node_child_fn!(identifier, Identifier);
    node_optional_child_fn!(generics_declaration, GenericsDeclaration);
    node_optional_child_fn!(argument_list_declaration, ArgumentListDeclaration);
    node_optional_child_fn!(generics_constraint, GenericsConstraint);
    node_optional_child_fn!(input_type, TypeExpr);
    node_optional_child_fn!(output_type, TypeExpr);
    node_children_iter_fn!(variants, VariantsIter);

    pub fn has_variants(&self) -> bool {
        !self.variants.is_empty()
    }

    pub fn callable_variants(&self) -> Vec<CallableVariant> {
        if self.has_variants() {
            self.variants.iter().map(|v| CallableVariant {
                generics_declarations: if let Some(generics_declaration) = v.generics_declaration() {
                    vec![generics_declaration]
                } else {
                    vec![]
                },
                argument_list_declaration: v.argument_list_declaration(),
                generics_constraints: if let Some(generics_constraint) = v.generics_constraint() {
                    vec![generics_constraint]
                } else {
                    vec![]
                },
                pipeline_input: Some(v.input_type().resolved().clone()),
                pipeline_output: Some(v.output_type().resolved().clone()),
            }).collect()
        } else {
            vec![CallableVariant {
                generics_declarations: if let Some(generics_declaration) = self.generics_declaration() {
                    vec![generics_declaration]
                } else {
                    vec![]
                },
                argument_list_declaration: self.argument_list_declaration(),
                generics_constraints: if let Some(generics_constraint) = self.generics_constraint() {
                    vec![generics_constraint]
                } else {
                    vec![]
                },
                pipeline_input: self.input_type().map(|t| t.resolved().clone()),
                pipeline_output: self.output_type().map(|t| t.resolved().clone()),
            }]
        }
    }
}

declare_container_node!(PipelineItemDeclarationVariant,
    pub(crate) comment: Option<usize>,
    pub(crate) generics_declaration: Option<usize>,
    pub(crate) argument_list_declaration: Option<usize>,
    pub(crate) generics_constraint: Option<usize>,
    pub(crate) input_type: usize,
    pub(crate) output_type: usize,
);

impl_container_node_defaults!(PipelineItemDeclarationVariant);

impl PipelineItemDeclarationVariant {

    node_optional_child_fn!(comment, DocComment);
    node_optional_child_fn!(generics_declaration, GenericsDeclaration);
    node_optional_child_fn!(argument_list_declaration, ArgumentListDeclaration);
    node_optional_child_fn!(generics_constraint, GenericsConstraint);
    node_child_fn!(input_type, TypeExpr);
    node_child_fn!(output_type, TypeExpr);
}


