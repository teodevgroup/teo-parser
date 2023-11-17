use std::cell::RefCell;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::type_expr::TypeExpr;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_optional_child_fn};
use crate::ast::doc_comment::DocComment;
use crate::format::Writer;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;
use crate::value::TypeAndValue;

declare_container_node!(Constant, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) type_expr: Option<usize>,
    pub(crate) expression: usize,
    pub(crate) resolved: RefCell<Option<TypeAndValue>>,
);

impl_container_node_defaults!(Constant, named, availability);

impl Constant {

    node_child_fn!(identifier, Identifier);

    node_optional_child_fn!(comment, DocComment);

    node_optional_child_fn!(type_expr, TypeExpr);

    node_child_fn!(expression, Expression);
}

impl InfoProvider for Constant {
    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Resolve<TypeAndValue> for Constant {
    fn resolved_ref_cell(&self) -> &RefCell<Option<TypeAndValue>> {
        &self.resolved
    }
}

impl Write for Constant {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }

    fn is_block_level_element(&self) -> bool {
        true
    }
}