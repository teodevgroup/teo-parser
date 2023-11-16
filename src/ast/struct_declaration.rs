use std::collections::BTreeMap;
use maplit::btreemap;
use crate::ast::doc_comment::DocComment;
use crate::ast::function_declaration::FunctionDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::{declare_container_node, impl_container_node_defaults, node_child_fn, node_children_iter, node_children_iter_fn, node_optional_child_fn};
use crate::format::Writer;
use crate::r#type::keyword::Keyword;
use crate::r#type::reference::Reference;
use crate::r#type::Type;
use crate::r#type::Type::StructObject;
use crate::traits::has_availability::HasAvailability;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::write::Write;

declare_container_node!(StructDeclaration, named, availability,
    pub(crate) comment: Option<usize>,
    pub(crate) identifier: usize,
    pub(crate) generics_declaration: Option<usize>,
    pub(crate) generics_constraint: Option<usize>,
    pub(crate) function_declarations: Vec<usize>,
);

impl_container_node_defaults!(StructDeclaration, named, availability);

node_children_iter!(StructDeclaration, FunctionDeclaration, FunctionsIter, function_declarations);

impl StructDeclaration {

    node_optional_child_fn!(comment, DocComment);
    node_child_fn!(identifier, Identifier);
    node_optional_child_fn!(generics_declaration, GenericsDeclaration);
    node_optional_child_fn!(generics_constraint, GenericsConstraint);
    node_children_iter_fn!(function_declarations, FunctionsIter);

    pub fn instance_function(&self, name: &str) -> Option<&FunctionDeclaration> {
        self.function_declarations().find(|f| !f.r#static && f.identifier().name() == name)
    }

    pub fn static_function(&self, name: &str) -> Option<&FunctionDeclaration> {
        self.function_declarations().find(|f| f.r#static && f.identifier().name() == name)
    }

    pub fn keywords_map(&self) -> BTreeMap<Keyword, Type> {
        btreemap! {
            Keyword::SelfIdentifier => StructObject(Reference::new(self.path.clone(), self.string_path.clone()), if let Some(generics_declaration) = self.generics_declaration() {
                generics_declaration.identifiers().map(|i| Type::GenericItem(i.name.clone())).collect()
            } else {
                vec![]
            })
        }
    }
}

impl InfoProvider for StructDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}

impl Write for StructDeclaration {
    fn write<'a>(&'a self, writer: &'a mut Writer<'a>) {
        writer.write_children(self, self.children.values());
    }
}