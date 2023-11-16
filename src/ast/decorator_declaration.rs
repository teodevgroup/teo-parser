use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::doc_comment::DocComment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::reference_space::ReferenceSpace;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::format::Writer;
use crate::traits::info_provider::InfoProvider;
use crate::traits::write::Write;

declare_container_node!(DecoratorDeclaration, named, availability,
    pub exclusive: bool,
    pub unique: bool,
    pub decorator_class: ReferenceSpace,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) generics_declaration: Option<usize>,
    pub(crate) argument_list_declaration: Option<usize>,
    pub(crate) generics_constraint: Option<usize>,
    pub(crate) variants: Vec<usize>,
);

impl_container_node_defaults!(DecoratorDeclaration, named, availability);

node_children_iter!(DecoratorDeclaration, DecoratorDeclarationVariant, VariantsIter, variants);

impl DecoratorDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(generics_declaration, GenericsDeclaration);

    node_optional_child_fn!(argument_list_declaration, ArgumentListDeclaration);

    node_optional_child_fn!(generics_constraint, GenericsConstraint);

    node_children_iter_fn!(variants, VariantsIter);

    pub fn has_variants(&self) -> bool {
        !self.variants.is_empty()
    }

    pub fn callable_variants(&self) -> Vec<CallableVariant> {
        if self.has_variants() {
            self.variants().map(|v| CallableVariant {
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
                pipeline_input: None,
                pipeline_output: None,
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
                pipeline_input: None,
                pipeline_output: None,
            }]
        }
    }
}

impl InfoProvider for DecoratorDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}

declare_container_node!(DecoratorDeclarationVariant,
    pub(crate) comment: Option<usize>,
    pub(crate) generics_declaration: Option<usize>,
    pub(crate) argument_list_declaration: Option<usize>,
    pub(crate) generics_constraint: Option<usize>,
);

impl_container_node_defaults!(DecoratorDeclarationVariant);

impl DecoratorDeclarationVariant {

    node_optional_child_fn!(comment, DocComment);

    node_optional_child_fn!(generics_declaration, GenericsDeclaration);

    node_optional_child_fn!(argument_list_declaration, ArgumentListDeclaration);

    node_optional_child_fn!(generics_constraint, GenericsConstraint);

}

impl Write for DecoratorDeclaration {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}

impl Write for DecoratorDeclarationVariant {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}