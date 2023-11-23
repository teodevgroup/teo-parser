use std::cell::RefCell;
use crate::ast::expression::Expression;
use crate::ast::identifier::Identifier;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_optional_child_fn};
use crate::format::Writer;
use crate::r#type::r#type::Type;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;
use crate::traits::write::Write;

declare_container_node!(
    Argument,
    pub(crate) name: Option<usize>,
    pub(crate) value: usize,
    pub(crate) resolved: RefCell<Option<ArgumentResolved>>
);

impl_container_node_defaults!(Argument);

impl Argument {

    node_optional_child_fn!(name, Identifier);

    node_child_fn!(value, Expression);

    pub fn get_type(&self) -> &Type {
        &self.value().resolved().r#type
    }

    pub fn resolve(&self, resolved: ArgumentResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &ArgumentResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }

    pub fn resolved_name(&self) -> Option<&str> {
        if let Some(name) = self.name() {
            Some(name.name())
        } else {
            if self.is_resolved() {
                Some(self.resolved().name.as_str())
            } else {
                None
            }
        }
    }
}

#[derive(Debug)]
pub struct ArgumentResolved {
    pub name: String,
    pub expect: Type,
    pub completion_expect: Option<Type>,
}

impl Write for Argument {
    fn write<'a>(&'a self, writer: &mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}