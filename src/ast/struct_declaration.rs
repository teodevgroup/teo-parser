use std::collections::BTreeMap;
use maplit::btreemap;
use crate::ast::availability::Availability;
use crate::ast::comment::Comment;
use crate::ast::function_declaration::FunctionDeclaration;
use crate::ast::generics::{GenericsConstraint, GenericsDeclaration};
use crate::ast::identifiable::Identifiable;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;
use crate::r#type::keyword::Keyword;
use crate::r#type::reference::Reference;
use crate::r#type::Type;
use crate::r#type::Type::StructObject;

#[derive(Debug)]
pub struct StructDeclaration {
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub define_availability: Availability,
    pub comment: Option<Comment>,
    pub identifier: Identifier,
    pub generics_declaration: Option<GenericsDeclaration>,
    pub generics_constraint: Option<GenericsConstraint>,
    pub function_declarations: Vec<FunctionDeclaration>,
    pub span: Span,
}

impl StructDeclaration {

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

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

    fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    fn path(&self) -> &Vec<usize> {
        &self.path
    }

    fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }
}