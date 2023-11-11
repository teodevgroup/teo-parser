use std::cell::RefCell;
use std::collections::BTreeMap;
use maplit::btreemap;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::function_declaration::FunctionDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::r#type::keyword::Keyword;
use crate::r#type::reference::Reference;
use crate::r#type::Type;
use crate::r#type::Type::StructObject;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;

#[derive(Debug)]
pub struct StructDeclaration {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub generics_declaration: Option<GenericsDeclaration>,
    pub generics_constraint: Option<GenericsConstraint>,
    pub function_declarations: Vec<FunctionDeclaration>,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
}

impl StructDeclaration {

    pub fn instance_function(&self, name: &str) -> Option<&FunctionDeclaration> {
        self.function_declarations.iter().find(|f| !f.r#static && f.identifier.name() == name)
    }

    pub fn static_function(&self, name: &str) -> Option<&FunctionDeclaration> {
        self.function_declarations.iter().find(|f| f.r#static && f.identifier.name() == name)
    }

    pub fn keywords_map(&self) -> BTreeMap<Keyword, Type> {
        btreemap! {
            Keyword::SelfIdentifier => StructObject(Reference::new(self.path.clone(), self.string_path.clone()), if let Some(generics_declaration) = self.generics_declaration.as_ref() {
                generics_declaration.identifiers.iter().map(|i| Type::GenericItem(i.name.clone())).collect()
            } else {
                vec![]
            })
        }
    }
}

impl Identifiable for StructDeclaration {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for StructDeclaration {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for StructDeclaration {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for StructDeclaration {
    fn namespace_skip(&self) -> usize {
        1
    }
}