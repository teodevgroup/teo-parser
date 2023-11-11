use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Mutex;
use maplit::btreeset;
use crate::availability::Availability;
use crate::ast::data_set::DataSetRecord;
use crate::ast::field::Field;
use crate::ast::namespace::Namespace;
use crate::ast::r#enum::EnumMember;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::span::Span;
use crate::diagnostics::diagnostics::{Diagnostics, DiagnosticsError, DiagnosticsWarning};
use crate::search::search_availability::{find_namespace_availability, find_source_availability};

#[derive(PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) struct ExaminedDataSetRecord {
    pub(crate) data_set: Vec<String>,
    pub(crate) group: Vec<String>,
    pub(crate) record: String,
}

pub(crate) struct ResolverContext<'a> {
    pub(crate) examined_default_paths_mysql: Mutex<BTreeSet<Vec<String>>>,
    pub(crate) examined_default_paths_postgres: Mutex<BTreeSet<Vec<String>>>,
    pub(crate) examined_default_paths_sqlite: Mutex<BTreeSet<Vec<String>>>,
    pub(crate) examined_default_paths_mongo: Mutex<BTreeSet<Vec<String>>>,
    pub(crate) examined_fields: Mutex<BTreeSet<String>>,
    pub(crate) examined_middleware_paths: Mutex<BTreeSet<Vec<String>>>,
    pub(crate) examined_data_set_records: Mutex<BTreeSet<ExaminedDataSetRecord>>,
    pub(crate) diagnostics: RefCell<&'a mut Diagnostics>,
    pub(crate) schema: &'a Schema,
    pub(crate) source: Mutex<Option<&'a Source>>,
    pub(crate) namespaces: Mutex<Vec<&'a Namespace>>,
    pub(crate) availabilities: Mutex<Vec<Availability>>,
}

impl<'a> ResolverContext<'a> {

    pub(crate) fn new(diagnostics: &'a mut Diagnostics, schema: &'a Schema) -> Self {
        Self {
            examined_default_paths_mysql: Mutex::new(btreeset!{}),
            examined_default_paths_postgres: Mutex::new(btreeset!{}),
            examined_default_paths_sqlite: Mutex::new(btreeset!{}),
            examined_default_paths_mongo: Mutex::new(btreeset!{}),
            examined_fields: Mutex::new(btreeset!{}),
            examined_middleware_paths: Mutex::new(btreeset!{}),
            examined_data_set_records: Mutex::new(btreeset!{}),
            diagnostics: RefCell::new(diagnostics),
            schema,
            source: Mutex::new(None),
            namespaces: Mutex::new(vec![]),
            availabilities: Mutex::new(vec![]),
        }
    }

    pub(crate) fn start_source(&self, source: &'a Source) {
        *self.source.lock().unwrap() = Some(source);
        // set availability
        let availability = find_source_availability(self.schema, source);
        *self.availabilities.lock().unwrap() = vec![availability];
    }

    pub(crate) fn push_namespace(&self, namespace: &'a Namespace) {
        self.namespaces.lock().unwrap().push(namespace);
        let availability = find_namespace_availability(namespace, self.schema, self.source());
        self.availabilities.lock().unwrap().push(availability);
    }

    pub(crate) fn pop_namespace(&self) {
        self.namespaces.lock().unwrap().pop();
        self.availabilities.lock().unwrap().pop();
    }

    pub(crate) fn current_availability(&self) -> Availability {
        *self.availabilities.lock().unwrap().last().unwrap()
    }

    pub(crate) fn source(&self) -> &Source {
        self.source.lock().unwrap().unwrap()
    }

    pub(crate) fn current_namespace(&self) -> Option<&Namespace> {
        self.namespaces.lock().unwrap().last().map(|r| *r)
    }

    pub(crate) fn add_examined_default_path(&self, path: Vec<String>, availability: Availability) {
        if availability.contains(Availability::mysql()) {
            self.examined_default_paths_mysql.lock().unwrap().insert(path.clone());
        }
        if availability.contains(Availability::postgres()) {
            self.examined_default_paths_postgres.lock().unwrap().insert(path.clone());
        }
        if availability.contains(Availability::sqlite()) {
            self.examined_default_paths_sqlite.lock().unwrap().insert(path.clone());
        }
        if availability.contains(Availability::mongo()) {
            self.examined_default_paths_mongo.lock().unwrap().insert(path.clone());
        }
    }

    pub(crate) fn has_examined_default_path(&self, path: &Vec<String>, availability: Availability) -> bool {
        if availability.contains(Availability::mysql()) {
            if self.examined_default_paths_mysql.lock().unwrap().contains(path) {
                return true;
            }
        }
        if availability.contains(Availability::postgres()) {
            if self.examined_default_paths_postgres.lock().unwrap().contains(path) {
                return true;
            }
        }
        if availability.contains(Availability::sqlite()) {
            if self.examined_default_paths_sqlite.lock().unwrap().contains(path) {
                return true;
            }
        }
        if availability.contains(Availability::mongo()) {
            if self.examined_default_paths_mongo.lock().unwrap().contains(path) {
                return true;
            }
        }
        false
    }

    pub(crate) fn add_examined_middleware_path(&self, path: Vec<String>) {
        self.examined_middleware_paths.lock().unwrap().insert(path);
    }

    pub(crate) fn has_examined_middleware_path(&self, path: &Vec<String>) -> bool {
        self.examined_middleware_paths.lock().unwrap().contains(path)
    }

    pub(crate) fn add_examined_field(&self, field: String) {
        self.examined_fields.lock().unwrap().insert(field);
    }

    pub(crate) fn has_examined_field(&self, field: &String) -> bool {
        self.examined_fields.lock().unwrap().contains(field)
    }

    pub(crate) fn clear_examined_fields(&self) {
        self.examined_fields.lock().unwrap().clear();
    }

    pub(crate) fn add_examined_data_set_record(&self, record: ExaminedDataSetRecord) {
        self.examined_data_set_records.lock().unwrap().insert(record);
    }

    pub(crate) fn has_examined_data_set_record(&self, record: &ExaminedDataSetRecord) -> bool {
        self.examined_data_set_records.lock().unwrap().contains(record)
    }
    
    pub(crate) fn diagnostics(&self) -> &'a mut Diagnostics {
        *(unsafe { &mut *self.diagnostics.as_ptr() })
    }

    pub(super) fn insert_duplicated_model_field_error(&'a self, field: &Field) {
        self.diagnostics().insert(DiagnosticsError::new(
            field.identifier.span,
            "Duplicated model field definition",
            self.source().file_path.clone()
        ))
    }

    pub(super) fn generate_diagnostics_error(&self, span: Span, message: impl Into<String>) -> DiagnosticsError {
        DiagnosticsError::new(
            span,
            message,
            self.source().file_path.clone()
        )
    }

    pub(super) fn insert_diagnostics_error(&self, span: Span, message: impl Into<String>) {
        self.diagnostics().insert(self.generate_diagnostics_error(span, message))
    }

    pub(super) fn insert_error(&self, error: DiagnosticsError) {
        self.diagnostics().insert(error)
    }

    pub(super) fn generate_diagnostics_warning(&self, span: Span, message: impl Into<String>) -> DiagnosticsWarning {
        DiagnosticsWarning::new(
            span,
            message,
            self.source().file_path.clone()
        )
    }

    pub(super) fn insert_diagnostics_warning(&self, span: Span, message: impl Into<String>) {
        self.diagnostics().insert(self.generate_diagnostics_warning(span, message))
    }

    pub(super) fn insert_duplicated_identifier(&self, span: Span) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            "TypeError: identifier is duplicated",
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_duplicated_enum_member_error(&self, enum_member: &EnumMember) {
        self.diagnostics().insert(DiagnosticsError::new(
            enum_member.identifier.span,
            "Duplicated enum member definition",
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_duplicated_data_set_record_error(&self, record: &DataSetRecord) {
        self.diagnostics().insert(DiagnosticsError::new(
            record.identifier.span,
            "Duplicated data set record",
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_unresolved_model(&self, span: Span) {
        self.diagnostics().insert_unresolved_model(span, self.source().file_path.clone())
    }

    pub(super) fn insert_unresolved_enum(&self, span: Span) {
        self.diagnostics().insert_unresolved_enum(span, self.source().file_path.clone())
    }

    pub(super) fn insert_data_set_record_key_type_is_not_string(&self, span: Span) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            "Data set record key is not string",
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_data_set_record_key_is_duplicated(&self, span: Span) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            "Data set record key is duplicated",
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_data_set_record_key_is_undefined(&self, span: Span, key: &str, model: &str) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            format!("Field with name '{key}' is undefined on model `{model}'"),
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_data_set_record_key_is_property(&self, span: Span) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            format!("Property is not allowed in data set record"),
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_data_set_record_key_is_dropped(&self, span: Span, key: &str, model: &str) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            format!("Field with name '{key}' is dropped on model `{model}'"),
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_data_set_record_primitive_value_type_error(&self, span: Span, message: String) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            message,
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_data_set_record_relation_value_is_not_array(&self, span: Span) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            "Relation value is not array",
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_data_set_record_relation_value_is_not_records_array(&self, span: Span, model_name: &str, dataset_path: &str) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            format!("Relation value is not array of `{model_name}` records in dataset `{dataset_path}`"),
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_data_set_record_relation_value_is_not_enum_variant(&self, span: Span, model_name: &str, dataset_path: &str) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            format!("Relation value is not enum variant of `{model_name}` records in dataset `{dataset_path}`"),
            self.source().file_path.clone()
        ))
    }
}
