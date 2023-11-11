use std::collections::{BTreeMap, HashMap, HashSet};
use maplit::btreemap;
use crate::availability::Availability;
use crate::ast::schema::SchemaReferences;
use crate::ast::span::Span;
use crate::diagnostics::diagnostics::{Diagnostics, DiagnosticsError, DiagnosticsWarning};
use crate::utils::path::FileUtility;

pub(super) struct ParserContext<'a> {
    pub(super) diagnostics: &'a mut Diagnostics,
    pub(super) schema_references: &'a mut SchemaReferences,
    pub(crate) file_util: FileUtility,
    pub(crate) unsaved_files: Option<HashMap<String, String>>,
    source_lookup: BTreeMap<usize, String>,
    current_source_id: usize,
    current_id: usize,
    current_path: Vec<usize>,
    current_string_path: Vec<String>,
    current_availability_flag_state: Vec<Availability>,
    current_source_is_builtin: bool,
    examined_import_file_paths: Vec<String>,
}

impl<'a> ParserContext<'a> {

    pub(crate) fn new(
        diagnostics: &'a mut Diagnostics,
        schema_references: &'a mut SchemaReferences,
        file_util: FileUtility,
        unsaved_files: Option<HashMap<String, String>>,
    ) -> ParserContext<'a> {
        Self {
            diagnostics,
            schema_references,
            file_util,
            unsaved_files,
            source_lookup: btreemap!{},
            current_source_id: 0,
            current_id: 0,
            current_path: vec![],
            current_string_path: vec![],
            current_availability_flag_state: vec![Availability::default()],
            current_source_is_builtin: false,
            examined_import_file_paths: vec![],
        }
    }

    pub(super) fn read_file(&self, file_path: &str) -> Option<String> {
        if let Some(unsaved_files) = &self.unsaved_files {
            if let Some(file_content) = unsaved_files.get(file_path) {
                return Some(file_content.clone());
            }
        }
        (self.file_util.read_file)(file_path)
    }

    pub(super) fn start_next_source(&mut self, path: String) -> usize {
        let source_id = self.next_id();
        self.source_lookup.insert(source_id, path);
        self.current_source_id = source_id;
        self.current_path = vec![source_id];
        self.current_string_path = vec![];
        self.current_availability_flag_state = vec![Availability::default()];
        self.examined_import_file_paths = vec![];
        self.current_source_is_builtin = false;
        source_id
    }

    pub(super) fn set_is_builtin_source(&mut self) {
        self.current_source_is_builtin = true;
    }

    pub(super) fn is_builtin_source(&self) -> bool {
        self.current_source_is_builtin
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

    pub(super) fn next_parent_string_path(&mut self, item: impl Into<String>) -> Vec<String> {
        self.current_string_path.push(item.into());
        self.current_string_path.clone()
    }

    pub(super) fn pop_string_path(&mut self) {
        self.current_string_path.pop();
    }

    pub(super) fn current_string_path(&self) -> Vec<String> {
        self.current_string_path.clone()
    }

    pub(super) fn current_path(&self) -> Vec<usize> {
        self.current_path.clone()
    }

    pub(super) fn is_source_parsing_or_parsed(&self, path: &str) -> bool {
        let set: HashSet<&String> = self.source_lookup.values().collect();
        set.iter().find(|p| p.as_str() == path).is_some()
    }

    pub(super) fn add_examined_import_file(&mut self, path: String) {
        self.examined_import_file_paths.push(path)
    }

    pub(super) fn is_import_file_path_examined(&self, path: &String) -> bool {
        self.examined_import_file_paths.contains(path)
    }

    pub(super) fn insert_unparsed(&mut self, span: Span) {
        let path = self.source_lookup.get(&self.current_source_id).unwrap();
        self.diagnostics.insert_unparsed_rule(span, path.clone());
    }

    pub(super) fn insert_invalid_decorator_declaration(&mut self, span: Span) {
        let path = self.source_lookup.get(&self.current_source_id).unwrap();
        self.diagnostics.insert(DiagnosticsError::new(span, "Decorator type is invalid", path.clone()));
    }

    pub(super) fn insert_error(&mut self, span: Span, message: impl Into<String>) {
        let path = self.source_lookup.get(&self.current_source_id).unwrap();
        self.diagnostics.insert(DiagnosticsError::new(span, message.into(), path.clone()));
    }

    pub(super) fn insert_warning(&mut self, span: Span, message: impl Into<String>) {
        let path = self.source_lookup.get(&self.current_source_id).unwrap();
        self.diagnostics.insert(DiagnosticsWarning::new(span, message.into(), path.clone()));
    }

    pub(super) fn push_availability_flag(&mut self, new_flag: Availability) -> Availability {
        let calculated_flag = self.current_availability_flag_state.last().unwrap().bi_and(new_flag);
        self.current_availability_flag_state.push(calculated_flag);
        calculated_flag
    }

    pub(super) fn pop_availability_flag(&mut self, span: Span) {
        if self.current_availability_flag_state.len() == 1 {
            self.insert_error(span,"unbalanced availability end")
        } else {
            self.current_availability_flag_state.pop();
        }
    }

    pub(super) fn current_availability_flag(&self) -> Availability {
        *self.current_availability_flag_state.last().unwrap()
    }
}