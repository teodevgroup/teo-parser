use crate::ast::namespace::Namespace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;

pub(crate) struct CompletionContext<'a> {
    pub(crate) schema: &'a Schema,
    pub(crate) source: &'a Source,
    pub(crate) namespaces: Vec<&'a Namespace>,
}

impl<'a> CompletionContext<'a> {

    pub(crate) fn new(schema: &'a Schema, source: &'a Source) -> Self {
        Self { schema, source, namespaces: vec![] }
    }

    pub(crate) fn push_namespace(&mut self, namespace: &'a Namespace) {
        self.namespaces.push(namespace);
    }

    pub(crate) fn current_namespace(&self) -> Option<&'a Namespace> {
        self.namespaces.last().map(|n| *n)
    }
}