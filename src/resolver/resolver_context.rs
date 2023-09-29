use std::collections::BTreeSet;
use std::sync::Mutex;
use maplit::btreeset;
use crate::ast::data_set::DataSetRecord;
use crate::ast::field::Field;
use crate::ast::model::Model;
use crate::ast::r#enum::{Enum, EnumMember};
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::span::Span;
use crate::diagnostics::diagnostics::{Diagnostics, DiagnosticsError};

#[derive(PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) struct ExaminedDataSetRecord {
    pub(crate) data_set: Vec<String>,
    pub(crate) group: Vec<String>,
    pub(crate) record: String,
}

pub(crate) struct ResolverContext<'a> {
    pub(crate) examined_model_paths: Mutex<BTreeSet<Vec<String>>>,
    pub(crate) examined_model_fields: Mutex<BTreeSet<String>>,
    pub(crate) examined_data_set_records: Mutex<BTreeSet<ExaminedDataSetRecord>>,
    pub(crate) diagnostics: &'a mut Diagnostics,
    pub(crate) schema: &'a Schema,
    pub(crate) source: Option<&'a Source>,
}

impl<'a> ResolverContext<'a> {

    pub(crate) fn new(diagnostics: &'a mut Diagnostics, schema: &'a Schema) -> Self {
        Self {
            examined_model_paths: Mutex::new(btreeset!{}),
            examined_model_fields: Mutex::new(btreeset!{}),
            examined_data_set_records: Mutex::new(btreeset!{}),
            diagnostics,
            schema,
            source: None,
        }
    }

    pub(crate) fn start_source(&mut self, source: &'a Source) {
        self.source = Some(source);
    }

    pub(crate) fn source(&self) -> &Source {
        self.source.unwrap()
    }

    pub(crate) fn add_examined_model_path(&self, model_path: Vec<String>) {
        self.examined_model_paths.lock().unwrap().insert(model_path);
    }

    pub(crate) fn has_examined_model_path(&self, model_path: &Vec<String>) -> bool {
        self.examined_model_paths.lock().unwrap().contains(model_path)
    }

    pub(crate) fn add_examined_model_field(&self, field: String) {
        self.examined_model_fields.lock().unwrap().insert(field);
    }

    pub(crate) fn has_examined_model_field(&self, field: &String) -> bool {
        self.examined_model_fields.lock().unwrap().contains(field)
    }

    pub(crate) fn clear_examined_model_fields(&self) {
        self.examined_model_fields.lock().unwrap().clear();
    }

    pub(crate) fn add_examined_data_set_record(&self, record: ExaminedDataSetRecord) {
        self.examined_data_set_records.lock().unwrap().insert(record);
    }

    pub(crate) fn has_examined_data_set_record(&self, record: &ExaminedDataSetRecord) -> bool {
        self.examined_data_set_records.lock().unwrap().contains(record)
    }

    pub(crate) fn insert_duplicated_model_error(&mut self, model: &Model) {
        self.diagnostics.insert(DiagnosticsError::new(
            model.identifier.span,
            "Duplicated model definition, identifier is defined",
            self.source().file_path.clone()
        ))
    }

    pub(crate) fn insert_duplicated_model_field_error(&self, field: &Field) {
        self.diagnostics.insert(DiagnosticsError::new(
            field.identifier.span,
            "Duplicated model field definition",
            self.source().file_path.clone()
        ))
    }

    fn insert_duplicated_enum_error(&self, r#enum: &Enum) {
        self.diagnostics.insert(DiagnosticsError::new(
            r#enum.identifier.span,
            "Duplicated enum definition, identifier is defined",
            self.source().file_path.clone()
        ))
    }

    fn insert_duplicated_enum_member_error(&self, enum_member: &EnumMember) {
        self.diagnostics.insert(DiagnosticsError::new(
            enum_member.identifier.span,
            "Duplicated enum member definition",
            self.source().file_path.clone()
        ))
    }

    fn insert_duplicated_data_set_record_error(&self, record: &DataSetRecord) {
        self.diagnostics.insert(DiagnosticsError::new(
            record.identifier.span,
            "Duplicated data set record",
            self.source().file_path.clone()
        ))
    }

    fn insert_unresolved_model(&self, span: Span) {
        self.diagnostics.insert_unresolved_model(span, self.source().file_path.clone())
    }

    fn insert_unresolved_enum(&self, span: Span) {
        self.diagnostics.insert_unresolved_enum(span, self.source().file_path.clone())
    }

    fn insert_data_set_record_key_type_is_not_string(&self, span: Span) {
        self.diagnostics.insert(DiagnosticsError::new(
            span,
            "Data set record key is not string",
            self.source().file_path.clone()
        ))
    }

    fn insert_data_set_record_key_is_duplicated(&self, span: Span) {
        self.diagnostics.insert(DiagnosticsError::new(
            span,
            "Data set record key is duplicated",
            self.source().file_path.clone()
        ))
    }

    fn insert_data_set_record_key_is_undefined(&self, span: Span, key: &str, model: &str) {
        self.diagnostics.insert(DiagnosticsError::new(
            span,
            format!("Field with name '{key}' is undefined on model `{model}'"),
            self.source().file_path.clone()
        ))
    }

    fn insert_data_set_record_key_is_property(&self, span: Span) {
        self.diagnostics.insert(DiagnosticsError::new(
            span,
            format!("Property is not allowed in data set record"),
            self.source().file_path.clone()
        ))
    }

    fn insert_data_set_record_key_is_dropped(&self, span: Span, key: &str, model: &str) {
        self.diagnostics.insert(DiagnosticsError::new(
            span,
            format!("Field with name '{key}' is dropped on model `{model}'"),
            self.source().file_path.clone()
        ))
    }

    fn insert_data_set_record_primitive_value_type_error(&self, span: Span, message: String) {
        self.diagnostics.insert(DiagnosticsError::new(
            span,
            message,
            self.source().file_path.clone()
        ))
    }

    fn insert_data_set_record_relation_value_is_not_array(&self, span: Span) {
        self.diagnostics.insert(DiagnosticsError::new(
            span,
            "Relation value is not array",
            self.source().file_path.clone()
        ))
    }

    fn insert_data_set_record_relation_value_is_not_records_array(&self, span: Span, model_name: &str, dataset_path: &str) {
        self.diagnostics.insert(DiagnosticsError::new(
            span,
            format!("Relation value is not array of `{model_name}` records in dataset `{dataset_path}`"),
            self.source().file_path.clone()
        ))
    }

    fn insert_data_set_record_relation_value_is_not_enum_variant(&self, span: Span, model_name: &str, dataset_path: &str) {
        self.diagnostics.insert(DiagnosticsError::new(
            span,
            format!("Relation value is not enum variant of `{model_name}` records in dataset `{dataset_path}`"),
            self.source().file_path.clone()
        ))
    }
}
