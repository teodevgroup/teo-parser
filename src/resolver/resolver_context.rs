use std::collections::BTreeSet;
use std::sync::Mutex;
use maplit::btreeset;
use crate::diagnostics::diagnostics::Diagnostics;

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
}

impl<'a> ResolverContext<'a> {

    pub(crate) fn new(diagnostics: &'a mut Diagnostics) -> Self {
        Self {
            examined_model_paths: Mutex::new(btreeset!{}),
            examined_model_fields: Mutex::new(btreeset!{}),
            examined_data_set_records: Mutex::new(btreeset!{}),
            diagnostics,
        }
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
}
