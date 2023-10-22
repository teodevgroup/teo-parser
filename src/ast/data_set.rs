use std::cell::RefCell;
use teo_teon::value::Value;
use crate::ast::availability::Availability;
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::literals::DictionaryLiteral;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct DataSet {
    pub span: Span,
    pub path: Vec<usize>,
    pub parent_path: Vec<String>,
    pub string_path: Vec<String>,
    pub identifier: Identifier,
    pub define_availability: Availability,
    pub auto_seed: bool,
    pub notrack: bool,
    pub groups: Vec<DataSetGroup>,
}

impl DataSet {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
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
    pub path: Vec<usize>,
    pub identifier_path: IdentifierPath,
    pub define_availability: Availability,
    pub span: Span,
    pub records: Vec<DataSetRecord>,
    pub resolved: RefCell<Option<DataSetGroupResolved>>,
}

#[derive(Debug)]
pub struct DataSetRecordResolved {
    value: Value,
}

#[derive(Debug)]
pub struct DataSetRecord {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub define_availability: Availability,
    pub identifier: Identifier,
    pub dictionary: DictionaryLiteral,
    pub resolved: RefCell<Option<DataSetRecordResolved>>,
}

impl DataSetRecord {

    pub fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    pub fn id(&self) -> usize {
        *self.path.last().unwrap()
    }
}