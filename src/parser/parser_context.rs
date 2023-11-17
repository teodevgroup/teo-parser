use std::backtrace;
use std::cell::{Cell, Ref, RefCell, RefMut};
use std::collections::{BTreeMap, HashSet};
use maplit::btreemap;
use crate::availability::Availability;
use crate::ast::schema::SchemaReferences;
use crate::ast::span::Span;
use crate::diagnostics::diagnostics::{Diagnostics, DiagnosticsError, DiagnosticsWarning};
use crate::utils::path::FileUtility;

pub(super) struct ParserContext {
    diagnostics: RefCell<Diagnostics>,
    schema_references: RefCell<SchemaReferences>,
    pub(crate) file_util: FileUtility,
    pub(crate) unsaved_files: Option<BTreeMap<String, String>>,
    source_lookup: RefCell<BTreeMap<usize, String>>,
    current_source_id: Cell<usize>,
    current_id: Cell<usize>,
    current_path: RefCell<Vec<usize>>,
    current_string_path: RefCell<Vec<String>>,
    current_availability_flag_state: RefCell<Vec<Availability>>,
    current_source_is_builtin: Cell<bool>,
    examined_import_file_paths: RefCell<Vec<String>>,
}

impl ParserContext {

    pub(crate) fn new(
        diagnostics: Diagnostics,
        schema_references: SchemaReferences,
        file_util: FileUtility,
        unsaved_files: Option<BTreeMap<String, String>>,
    ) -> ParserContext {
        Self {
            diagnostics: RefCell::new(diagnostics),
            schema_references: RefCell::new(schema_references),
            file_util,
            unsaved_files,
            source_lookup: RefCell::new(btreemap!{}),
            current_source_id: Cell::new(0),
            current_id: Cell::new(0),
            current_path: RefCell::new(vec![]),
            current_string_path: RefCell::new(vec![]),
            current_availability_flag_state: RefCell::new(vec![Availability::default()]),
            current_source_is_builtin: Cell::new(false),
            examined_import_file_paths: RefCell::new(vec![]),
        }
    }

    pub(super) fn diagnostics(&self) -> Ref<'_, Diagnostics> {
        self.diagnostics.borrow()
    }

    pub(super) fn diagnostics_mut(&self) -> RefMut<'_, Diagnostics> {
        self.diagnostics.borrow_mut()
    }

    pub(super) fn schema_references(&self) -> Ref<'_, SchemaReferences> {
        self.schema_references.borrow()
    }

    pub(super) fn schema_references_mut(&self) -> RefMut<'_, SchemaReferences> {
        self.schema_references.borrow_mut()
    }

    pub(super) fn read_file(&self, file_path: &str) -> Option<String> {
        if let Some(unsaved_files) = &self.unsaved_files {
            if let Some(file_content) = unsaved_files.get(file_path) {
                return Some(file_content.clone());
            }
        }
        (self.file_util.read_file)(file_path)
    }

    pub(super) fn start_next_source(&self, path: String) -> usize {
        let source_id = self.next_id();
        self.source_lookup.borrow_mut().insert(source_id, path);
        self.current_source_id.set(source_id);
        *self.current_path.borrow_mut() = vec![source_id];
        *self.current_string_path.borrow_mut() = vec![];
        *self.current_availability_flag_state.borrow_mut() = vec![Availability::default()];
        *self.examined_import_file_paths.borrow_mut() = vec![];
        self.current_source_is_builtin.set(false);
        source_id
    }

    pub(super) fn set_is_builtin_source(&self) {
        self.current_source_is_builtin.set(true);
    }

    pub(super) fn is_builtin_source(&self) -> bool {
        self.current_source_is_builtin.get()
    }

    pub(super) fn next_id(&self) -> usize {
        self.current_id.set(self.current_id.get() + 1);
        self.current_id.get()
    }

    pub(super) fn pop_parent_id(&self) {
        self.current_path.borrow_mut().pop();
    }

    pub(super) fn next_path(&self) -> Vec<usize> {
        let id = self.next_id();
        let mut path = self.current_path.borrow().clone();
        path.push(id);
        path
    }

    pub(super) fn next_parent_path(&self) -> Vec<usize> {
        let id = self.next_id();
        self.current_path.borrow_mut().push(id);
        self.current_path.borrow().clone()
    }

    pub(super) fn next_string_path(&self, item: impl Into<String>) -> Vec<String> {
        let mut string_path = self.current_string_path.borrow().clone();
        string_path.push(item.into());
        string_path
    }

    pub(super) fn next_parent_string_path(&self, item: impl Into<String>) -> Vec<String> {
        self.current_string_path.borrow_mut().push(item.into());
        self.current_string_path.borrow().clone()
    }

    pub(super) fn pop_string_path(&self) {
        self.current_string_path.borrow_mut().pop();
    }

    pub(super) fn current_string_path(&self) -> Vec<String> {
        self.current_string_path.borrow().clone()
    }

    pub(super) fn current_path(&self) -> Vec<usize> {
        self.current_path.borrow().clone()
    }

    pub(super) fn is_source_parsing_or_parsed(&self, path: &str) -> bool {
        let binding = self.source_lookup.borrow();
        let set: HashSet<&String> = binding.values().collect();
        set.iter().find(|p| p.as_str() == path).is_some()
    }

    pub(super) fn add_examined_import_file(&self, path: String) {
        self.examined_import_file_paths.borrow_mut().push(path)
    }

    pub(super) fn is_import_file_path_examined(&self, path: &String) -> bool {
        self.examined_import_file_paths.borrow().contains(path)
    }

    pub(super) fn insert_unparsed(&self, span: Span) {
        let binding = self.source_lookup.borrow();
        let path = binding.get(&self.current_source_id.get()).unwrap();
        self.diagnostics_mut().insert_unparsed_rule(span, path.clone());
    }

    pub(super) fn insert_invalid_decorator_declaration(&self, span: Span) {
        let binding = self.source_lookup.borrow();
        let path = binding.get(&self.current_source_id.get()).unwrap();
        self.diagnostics_mut().insert(DiagnosticsError::new(span, "decorator type is invalid", path.clone()));
    }

    pub(super) fn insert_error(&self, span: Span, message: impl Into<String>) {
        let binding = self.source_lookup.borrow();
        let path = binding.get(&self.current_source_id.get()).unwrap();
        self.diagnostics_mut().insert(DiagnosticsError::new(span, message.into(), path.clone()));
    }

    pub(super) fn insert_unattached_doc_comment(&self, span: Span) {
        self.insert_warning(span, "unattached doc comment");
    }

    pub(super) fn insert_warning(&self, span: Span, message: impl Into<String>) {
        let binding = self.source_lookup.borrow();
        let path = binding.get(&self.current_source_id.get()).unwrap();
        self.diagnostics_mut().insert(DiagnosticsWarning::new(span, message.into(), path.clone()));
    }

    pub(super) fn push_availability_flag(&self, new_flag: Availability) -> Availability {
        let calculated_flag = self.current_availability_flag_state.borrow().last().unwrap().bi_and(new_flag);
        self.current_availability_flag_state.borrow_mut().push(calculated_flag);
        calculated_flag
    }

    pub(super) fn pop_availability_flag(&self, span: Span) {
        if self.current_availability_flag_state.borrow().len() == 1 {
            self.insert_error(span,"unbalanced availability end")
        } else {
            self.current_availability_flag_state.borrow_mut().pop();
        }
    }

    pub(super) fn current_availability_flag(&self) -> Availability {
        *self.current_availability_flag_state.borrow().last().unwrap()
    }
}
