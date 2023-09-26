use std::collections::{BTreeMap, HashSet};
use maplit::btreemap;
use crate::ast::schema::SchemaReferences;
use crate::ast::span::Span;
use crate::diagnostics::diagnostics::{Diagnostics, DiagnosticsError, DiagnosticsWarning};

pub(super) struct ParserContext<'a> {
    pub(super) diagnostics: &'a mut Diagnostics,
    pub(super) schema_references: &'a mut SchemaReferences,
    source_lookup: BTreeMap<usize, String>,
    current_source_id: usize,
    current_id: usize,
    current_path: Vec<usize>,
    current_string_path: Vec<String>,
}

impl<'a> ParserContext<'a> {

    pub(crate) fn new(
        diagnostics: &'a mut Diagnostics,
        schema_references: &'a mut SchemaReferences
    ) -> ParserContext<'a> {
        Self {
            diagnostics,
            schema_references,
            source_lookup: btreemap!{},
            current_source_id: 0,
            current_id: 0,
            current_path: vec![],
            current_string_path: vec![],
        }
    }

    pub(super) fn start_next_source(&mut self, path: String) -> usize {
        let source_id = self.next_id();
        self.source_lookup.insert(source_id, path);
        self.current_source_id = source_id;
        self.current_path = vec![source_id];
        self.current_string_path = vec![];
        source_id
    }

    pub(super) fn next_id(&mut self) -> usize {
        self.current_id += 1;
        self.current_id
    }

    pub(super) fn next_parent_id(&mut self) -> usize {
        let id = self.next_id();
        self.current_path.push(id);
        id
    }

    pub(super) fn pop_parent_id(&mut self) {
        self.current_path.pop();
    }

    pub(super) fn next_path(&mut self) -> Vec<usize> {
        let id = self.next_id();
        let mut path = self.current_path.clone();
        path.push(id);
        path
    }

    pub(super) fn next_parent_path(&mut self) -> Vec<usize> {
        self.next_parent_id();
        self.current_path.clone()
    }

    pub(super) fn next_string_path(&self, item: impl Into<String>) -> Vec<String> {
        let mut string_path = self.current_string_path.clone();
        string_path.push(item.into());
        string_path
    }


    pub(super) fn push_string_path(&mut self, item: impl Into<String>) {
        self.current_string_path.push(item.into())
    }

    pub(super) fn pop_string_path(&mut self) {
        self.current_string_path.pop();
    }

    pub(super) fn is_source_parsing_or_parsed(&self, path: &String) -> bool {
        let set: HashSet<&String> = self.source_lookup.values().collect();
        set.contains(path)
    }

    pub(super) fn insert_unparsed(&mut self, span: Span) {
        let path = self.source_lookup.get(&self.current_source_id).unwrap();
        self.diagnostics.insert_unparsed_rule(span, path.clone());
    }

    pub(super) fn insert_error(&mut self, span: Span, message: impl Into<String>) {
        let path = self.source_lookup.get(&self.current_source_id).unwrap();
        self.diagnostics.insert(DiagnosticsError::new(span, message.into(), path.clone()));
    }

    pub(super) fn insert_warning(&mut self, span: Span, message: impl Into<String>) {
        let path = self.source_lookup.get(&self.current_source_id).unwrap();
        self.diagnostics.insert(DiagnosticsWarning::new(span, message.into(), path.clone()));
    }
}