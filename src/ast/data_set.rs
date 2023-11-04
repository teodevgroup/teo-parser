use std::cell::RefCell;
use teo_teon::value::Value;
use crate::ast::availability::Availability;
use crate::ast::identifiable::Identifiable;
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::info_provider::InfoProvider;
use crate::ast::literals::DictionaryLiteral;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct DataSetResolved {
    pub actual_availability: Availability,
}

#[derive(Debug)]
pub struct DataSet {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub identifier: Identifier,
    pub define_availability: Availability,
    pub auto_seed: bool,
    pub notrack: bool,
    pub groups: Vec<DataSetGroup>,
    pub resolved: RefCell<Option<DataSetResolved>>,
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

    pub fn resolve(&self, resolved: DataSetResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &DataSetResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

impl Identifiable for DataSet {

    fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    fn path(&self) -> &Vec<usize> {
        &self.path
    }

    fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }
}

impl InfoProvider for DataSet {
    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(1).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}

#[derive(Debug)]
pub struct DataSetGroupResolved {
    pub model_path: Vec<usize>,
    pub model_string_path: Vec<String>,
    pub actual_availability: Availability,
}

#[derive(Debug)]
pub struct DataSetGroup {
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub identifier_path: IdentifierPath,
    pub define_availability: Availability,
    pub span: Span,
    pub records: Vec<DataSetRecord>,
    pub resolved: RefCell<Option<DataSetGroupResolved>>,
}

impl DataSetGroup {

    pub fn resolve(&self, resolved: DataSetGroupResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &DataSetGroupResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

impl Identifiable for DataSetGroup {

    fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    fn path(&self) -> &Vec<usize> {
        &self.path
    }

    fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }
}

impl InfoProvider for DataSetGroup {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(2).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}

#[derive(Debug)]
pub struct DataSetRecordResolved {
    pub value: Value,
    pub actual_availability: Availability,
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

    pub fn resolve(&self, resolved: DataSetRecordResolved) {
        *(unsafe { &mut *self.resolved.as_ptr() }) = Some(resolved);
    }

    pub fn resolved(&self) -> &DataSetRecordResolved {
        (unsafe { &*self.resolved.as_ptr() }).as_ref().unwrap()
    }

    pub fn is_resolved(&self) -> bool {
        self.resolved.borrow().is_some()
    }
}

impl Identifiable for DataSetRecord {

    fn source_id(&self) -> usize {
        *self.path.first().unwrap()
    }

    fn id(&self) -> usize {
        *self.path.last().unwrap()
    }

    fn path(&self) -> &Vec<usize> {
        &self.path
    }

    fn str_path(&self) -> Vec<&str> {
        self.string_path.iter().map(AsRef::as_ref).collect()
    }
}

impl InfoProvider for DataSetRecord {

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path.iter().rev().skip(2).rev().map(AsRef::as_ref).collect()
    }

    fn availability(&self) -> Availability {
        self.define_availability.bi_and(self.resolved().actual_availability)
    }
}