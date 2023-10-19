use std::cell::RefCell;
use teo_teon::value::Value;
use crate::ast::availability::Availability;
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::literals::DictionaryLiteral;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct DataSet {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) parent_path: Vec<String>,
    pub(crate) string_path: Vec<String>,
    pub(crate) identifier: Identifier,
    pub(crate) define_availability: Availability,
    pub(crate) auto_seed: bool,
    pub(crate) notrack: bool,
    pub(crate) groups: Vec<DataSetGroup>,
}

impl DataSet {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    pub fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }
}

#[derive(Debug)]
pub struct DataSetGroupResolved {
    model_path: Vec<usize>,
}

#[derive(Debug)]
pub struct DataSetGroup {
    pub(crate) path: Vec<usize>,
    pub(crate) identifier_path: IdentifierPath,
    pub(crate) define_availability: Availability,
    pub(crate) span: Span,
    pub(crate) records: Vec<DataSetRecord>,
    pub(crate) resolved: RefCell<Option<DataSetGroupResolved>>,
}

#[derive(Debug)]
pub struct DataSetRecordResolved {
    value: Value,
}

#[derive(Debug)]
pub struct DataSetRecord {
    pub(crate) span: Span,
    pub(crate) path: Vec<usize>,
    pub(crate) string_path: Vec<String>,
    pub(crate) define_availability: Availability,
    pub(crate) identifier: Identifier,
    pub(crate) dictionary: DictionaryLiteral,
    pub(crate) resolved: RefCell<Option<DataSetRecordResolved>>,
}

impl DataSetRecord {

    pub(crate) fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub(crate) fn id(&self) -> usize {
        *self.path.last().unwrap()
    }
}