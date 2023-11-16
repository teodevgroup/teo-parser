use std::cell::RefCell;
use teo_teon::value::Value;
use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::availability::Availability;
use crate::ast::callable_variant::CallableVariant;
use crate::ast::doc_comment::DocComment;
use crate::ast::decorator::Decorator;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::format::Writer;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(Enum, named, availability,
    pub interface: bool,
    pub option: bool,
    pub(crate) comment: Option<usize>,
    pub(crate) decorators: Vec<usize>,
    pub(crate) identifier: usize,
    pub(crate) members: Vec<usize>,
);

impl_container_node_defaults!(Enum, named, availability);

node_children_iter!(Enum, Decorator, EnumDecoratorsIter, decorators);

node_children_iter!(Enum, EnumMember, EnumMembersIter, members);

impl Enum {

    node_optional_child_fn!(comment, DocComment);

    node_child_fn!(identifier, Identifier);

    node_children_iter_fn!(decorators, EnumDecoratorsIter);

    node_children_iter_fn!(members, EnumMembersIter);
}

impl InfoProvider for Enum {
    fn namespace_skip(&self) -> usize {
        1
    }
}

declare_container_node!(EnumMember, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) decorators: Vec<usize>,
    pub(crate) identifier: usize,
    pub(crate) expression: Option<usize>,
    pub(crate) argument_list_declaration: Option<usize>,
    pub(crate) resolved: RefCell<Option<Value>>,
);

impl_container_node_defaults!(EnumMember, named, availability);

node_children_iter!(EnumMember, Decorator, EnumMemberDecoratorsIter, decorators);

impl EnumMember {

    node_optional_child_fn!(comment, DocComment);

    node_children_iter_fn!(decorators, EnumMemberDecoratorsIter);

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(expression, Expression);

    node_optional_child_fn!(argument_list_declaration, ArgumentListDeclaration);

    pub fn callable_variants(&self) -> Vec<CallableVariant> {
        self.argument_list_declaration().map(|a| CallableVariant {
            generics_declarations: vec![],
            argument_list_declaration: Some(a),
            generics_constraints: vec![],
            pipeline_input: None,
            pipeline_output: None,
        }).into_iter().collect()
    }
}

impl InfoProvider for EnumMember {
    fn namespace_skip(&self) -> usize {
        2
    }
}

impl Resolve<Value> for EnumMember {

    fn resolved_ref_cell(&self) -> &RefCell<Option<Value>> {
        &self.resolved
    }
}

impl Write for Enum {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}

impl Write for EnumMember {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}