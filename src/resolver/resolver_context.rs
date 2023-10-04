use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Mutex;
use maplit::btreeset;
use teo_teon::value::Value;
use crate::ast::data_set::DataSetRecord;
use crate::ast::field::Field;
use crate::ast::namespace::Namespace;
use crate::ast::r#enum::{Enum, EnumMember};
use crate::ast::r#type::Type;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::span::Span;
use crate::diagnostics::diagnostics::{Diagnostics, DiagnosticsError, DiagnosticsWarning};

#[derive(PartialEq, Eq, Hash, Ord, PartialOrd)]
pub(crate) struct ExaminedDataSetRecord {
    pub(crate) data_set: Vec<String>,
    pub(crate) group: Vec<String>,
    pub(crate) record: String,
}

pub(crate) struct ResolverContext<'a> {
    pub(crate) examined_default_paths: Mutex<BTreeSet<Vec<String>>>,
    pub(crate) examined_fields: Mutex<BTreeSet<String>>,
    pub(crate) examined_middleware_paths: Mutex<BTreeSet<Vec<String>>>,
    pub(crate) examined_action_paths: Mutex<BTreeSet<Vec<String>>>,
    pub(crate) examined_data_set_records: Mutex<BTreeSet<ExaminedDataSetRecord>>,
    pub(crate) diagnostics: RefCell<&'a mut Diagnostics>,
    pub(crate) schema: &'a Schema,
    pub(crate) source: Mutex<Option<&'a Source>>,
    pub(crate) namespaces: Mutex<Vec<&'a Namespace>>,
}

impl<'a> ResolverContext<'a> {

    pub(crate) fn new(diagnostics: &'a mut Diagnostics, schema: &'a Schema) -> Self {
        Self {
            examined_default_paths: Mutex::new(btreeset!{}),
            examined_fields: Mutex::new(btreeset!{}),
            examined_middleware_paths: Mutex::new(btreeset!{}),
            examined_action_paths: Mutex::new(btreeset!{}),
            examined_data_set_records: Mutex::new(btreeset!{}),
            diagnostics: RefCell::new(diagnostics),
            schema,
            source: Mutex::new(None),
            namespaces: Mutex::new(vec![]),
        }
    }

    pub(crate) fn start_source(&self, source: &'a Source) {
        *self.source.lock().unwrap() = Some(source);
    }

    pub(crate) fn push_namespace(&self, namespace: &'a Namespace) {
        self.namespaces.lock().unwrap().push(namespace);
    }

    pub(crate) fn pop_namespace(&self) {
        self.namespaces.lock().unwrap().pop();
    }

    pub(crate) fn source(&self) -> &Source {
        self.source.lock().unwrap().unwrap()
    }

    pub(crate) fn current_namespace(&self) -> Option<&Namespace> {
        self.namespaces.lock().unwrap().last().map(|r| *r)
    }

    pub(crate) fn add_examined_default_path(&self, path: Vec<String>) {
        self.examined_default_paths.lock().unwrap().insert(path);
    }

    pub(crate) fn has_examined_default_path(&self, path: &Vec<String>) -> bool {
        self.examined_default_paths.lock().unwrap().contains(path)
    }

    pub(crate) fn add_examined_middleware_path(&self, path: Vec<String>) {
        self.examined_middleware_paths.lock().unwrap().insert(path);
    }

    pub(crate) fn has_examined_middleware_path(&self, path: &Vec<String>) -> bool {
        self.examined_middleware_paths.lock().unwrap().contains(path)
    }

    pub(crate) fn add_examined_action_path(&self, path: Vec<String>) {
        self.examined_action_paths.lock().unwrap().insert(path);
    }

    pub(crate) fn has_examined_action_path(&self, path: &Vec<String>) -> bool {
        self.examined_action_paths.lock().unwrap().contains(path)
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

    pub(crate) fn check_value_type(&self, r#type: &Type, value: &Value) -> bool {
        match r#type {
            Type::Any => true,
            Type::Null => value.is_null(),
            Type::Bool => value.is_bool(),
            Type::Int => value.is_i(),
            Type::Int64 => value.is_i(),
            Type::Float32 => value.is_f(),
            Type::Float => value.is_f(),
            Type::Decimal => value.is_decimal(),
            Type::String => value.is_string(),
            Type::ObjectId => value.is_object_id(),
            Type::Date => value.is_date(),
            Type::DateTime => value.is_datetime(),
            Type::File => value.is_file(),
            Type::Array(inner) => {
                if !value.is_vec() {
                    return false;
                }
                value.as_vec().unwrap().iter().find(|v| !self.check_value_type(inner.as_ref(), v)).is_none()
            }
            Type::Dictionary(k, vt) => {
                if !k.is_string() {
                    return false;
                }
                if !value.is_hashmap() {
                    return false;
                }
                value.as_hashmap().unwrap().values().find(|v| !self.check_value_type(vt.as_ref(), v)).is_none()
            }
            Type::Tuple(v) => {
                if !value.is_tuple() {
                    return false;
                }
                let tuple = value.as_tuple().unwrap();
                if v.len() != tuple.len() {
                    return false;
                }
                tuple.iter().enumerate().find(|(index, val)| !self.check_value_type(v.get(*index).unwrap(), val)).is_none()
            }
            Type::Range(inner) => {
                if !value.is_range() {
                    return false;
                }
                let range = value.as_range().unwrap();
                if !self.check_value_type(inner.as_ref(), range.start.as_ref()) {
                    return false;
                }
                if !self.check_value_type(inner.as_ref(), range.end.as_ref()) {
                    return false;
                }
                true
            }
            Type::Union(u) => {
                for t in u {
                    if self.check_value_type(t, value) {
                        return true;
                    }
                }
                false
            }
            Type::Ignored => true,
            Type::Enum(enum_path) => {
                if !value.is_raw_enum_variant() {
                    return false;
                }
                let e = self.schema.find_top_by_path(enum_path).unwrap().as_enum().unwrap();
                let name = value.as_raw_enum_variant().unwrap();
                for member in &e.members {
                    if member.identifier.name() == name {
                        return true;
                    }
                }
                false
            },
            Type::Model(_) => false,
            Type::Interface(_, __) => false,
            Type::ModelScalarField(_) => false,
            Type::ModelScalarFieldAndCachedProperty(_) => false,
            Type::FieldType(_, _) => false,
            Type::GenericItem(_) => false,
            Type::Optional(inner) => {
                if value.is_null() {
                    return true;
                }
                self.check_value_type(inner.as_ref(), value)
            }
            Type::Keyword(k) => false,
            Type::Object(o) => false,
            Type::Unresolved => false,
        }

    }

    // pub(crate) fn display_type(&self, r#type: &Type) -> String {
    //     match self {
    //         Type::Any => f.write_str("Any"),
    //         Type::Null => f.write_str("Null"),
    //         Type::Bool => f.write_str("Bool"),
    //         Type::Int => f.write_str("Int"),
    //         Type::Int64 => f.write_str("Int64"),
    //         Type::Float32 => f.write_str("Float32"),
    //         Type::Float => f.write_str("Float"),
    //         Type::Decimal => f.write_str("Decimal"),
    //         Type::String => f.write_str("String"),
    //         Type::ObjectId => f.write_str("ObjectId"),
    //         Type::Date => f.write_str("Date"),
    //         Type::DateTime => f.write_str("DateTime"),
    //         Type::File => f.write_str("File"),
    //         Type::Array(inner) => {
    //             Display::fmt(inner.as_ref(), f)?;
    //             f.write_str("[]")
    //         }
    //         Type::Dictionary(k, v) => {
    //             if k.is_string() {
    //                 Display::fmt(v.as_ref(), f)?;
    //                 f.write_str("{}")
    //             } else {
    //                 f.write_str("Dictionary<")?;
    //                 Display::fmt(k.as_ref(), f)?;
    //                 f.write_str(", ")?;
    //                 Display::fmt(v.as_ref(), f)?;
    //                 f.write_str(">")
    //             }
    //         }
    //         Type::Tuple(v) => {
    //             f.write_str("(")?;
    //             for (i, t) in v.iter().enumerate() {
    //                 Display::fmt(t, f)?;
    //                 if i != v.len() - 1 {
    //                     f.write_str(", ")?;
    //                 }
    //             }
    //             f.write_str(")")
    //         }
    //         Type::Range(inner) => {
    //             f.write_str("Range<")?;
    //             Display::fmt(inner.as_ref(), f)?;
    //             f.write_str(">")
    //         }
    //         Type::Union(v) => {
    //             for (i, t) in v.iter().enumerate() {
    //                 Display::fmt(t, f)?;
    //                 if i != v.len() - 1 {
    //                     f.write_str(" | ")?;
    //                 }
    //             }
    //         }
    //         Type::Ignored => f.write_str("Ignored"),
    //         Type::Enum(e) => {
    //
    //         }
    //         Type::Model(_) => {}
    //         Type::Interface(_, _) => {}
    //         Type::ModelScalarField(_) => {}
    //         Type::ModelScalarFieldAndCachedProperty(_) => {}
    //         Type::FieldType(_, _) => {}
    //         Type::GenericItem(_) => {}
    //         Type::Optional(_) => {}
    //         Type::Keyword(_) => {}
    //         Type::Object(_) => {}
    //         Type::Unresolved => {}
    //     }
    // }
    
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

    pub(super) fn insert_diagnostics_error(&self, span: Span, message: impl Into<String>) {
        self.diagnostics().insert(DiagnosticsError::new(
            span,
            message,
            self.source().file_path.clone()
        ))
    }

    pub(super) fn insert_diagnostics_warning(&self, span: Span, message: impl Into<String>) {
        self.diagnostics().insert(DiagnosticsWarning::new(
            span,
            message,
            self.source().file_path.clone()
        ))
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
