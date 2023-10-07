use crate::ast::schema::Schema;
use crate::ast::source::Source;

pub(crate) struct CompletionContext<'a> {
    pub(crate) schema: &'a Schema,
    pub(crate) source: &'a Source,
    pub(crate) reviewed_sources: Vec<&'a str>,
}

impl<'a> CompletionContext<'a> {

    pub(crate) fn new(schema: &'a Schema, source: &'a Source) -> Self {
        Self { schema, source, reviewed_sources: vec![] }
    }
}