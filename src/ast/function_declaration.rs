use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::doc_comment::DocComment;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::ast::struct_declaration::StructDeclaration;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_optional_child_fn};
use crate::traits::info_provider::InfoProvider;

declare_container_node!(FunctionDeclaration, named, availability,
    pub r#static: bool,
    pub inside_struct: bool,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) generics_declaration: Option<usize>,
    pub(crate) argument_list_declaration: usize,
    pub(crate) generics_constraint: Option<usize>,
    pub(crate) return_type: usize,
);

impl_container_node_defaults!(FunctionDeclaration, named, availability);

impl FunctionDeclaration {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(generics_declaration, GenericsDeclaration);

    node_child_fn!(argument_list_declaration, ArgumentListDeclaration);

    node_optional_child_fn!(generics_constraint, GenericsConstraint);

    node_optional_child_fn!(return_type, TypeExpr);

    pub fn callable_variants<'a>(&'a self, struct_declaration: &'a StructDeclaration) -> Vec<CallableVariant<'a>> {
        let mut generics_declaration = vec![];
        let mut generics_constraint = vec![];
        if let Some(d) = struct_declaration.generics_declaration() {
            generics_declaration.push(d);
        }
        if let Some(d) = struct_declaration.generics_constraint() {
            generics_constraint.push(d);
        }
        if let Some(d) = self.generics_declaration() {
            generics_declaration.push(d);
        }
        if let Some(d) = self.generics_constraint() {
            generics_constraint.push(d);
        }
        vec![CallableVariant {
            generics_declarations: generics_declaration,
            argument_list_declaration: Some(self.argument_list_declaration()),
            generics_constraints: generics_constraint,
            pipeline_input: None,
            pipeline_output: None,
        }]
    }
}

impl InfoProvider for FunctionDeclaration {

    fn namespace_skip(&self) -> usize {
        if self.inside_struct {
            2
        } else {
            1
        }
    }
}