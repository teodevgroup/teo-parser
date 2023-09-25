use std::collections::BTreeMap;
use maplit::btreemap;
use crate::ast::span::Span;
use crate::diagnostics::diagnostics::Diagnostics;

pub(super) struct ParserContext<'a> {
    pub(super) diagnostics: &'a mut Diagnostics,
    source_lookup: BTreeMap<usize, String>,
    current_source_id: usize,
    current_id: usize,
}

impl<'a> ParserContext<'a> {

    pub(super) fn new(diagnostics: &'a mut Diagnostics) -> ParserContext<'a> {
        Self {
            diagnostics,
            source_lookup: btreemap!{},
            current_source_id: 0,
            current_id: 0,
        }
    }

    pub(super) fn next_id(&mut self) -> usize {
        self.current_id += 1;
        self.current_id
    }

    pub(super) fn start_next_source(&mut self, path: String) -> usize {
        let source_id = self.next_id();
        self.source_lookup.insert(source_id, path);
        self.current_source_id = source_id;
        source_id
    }

    pub(super) fn insert_unparsed(&mut self, span: Span) {
        let path = self.source_lookup.get(&self.current_source_id).unwrap();
        self.diagnostics.insert_unparsed_rule(span, path.clone());
    }
}