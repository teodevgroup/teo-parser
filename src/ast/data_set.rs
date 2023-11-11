use std::cell::RefCell;
use teo_teon::value::Value;
use crate::ast::availability::Availability;
use crate::ast::identifier::Identifier;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::literals::DictionaryLiteral;
use crate::ast::span::Span;
use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::info_provider::InfoProvider;
use crate::traits::named_identifiable::NamedIdentifiable;
use crate::traits::resolved::Resolve;

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
    pub actual_availability: RefCell<Availability>,
}

impl Identifiable for DataSet {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for DataSet {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for DataSet {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for DataSet {
    fn namespace_skip(&self) -> usize {
        1
    }
}

#[derive(Debug)]
pub struct DataSetGroupResolved {
    pub model_path: Vec<usize>,
    pub model_string_path: Vec<String>,
}

#[derive(Debug)]
pub struct DataSetGroup {
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub identifier_path: IdentifierPath,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
    pub span: Span,
    pub records: Vec<DataSetRecord>,
    pub resolved: RefCell<Option<DataSetGroupResolved>>,
}

impl Identifiable for DataSetGroup {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for DataSetGroup {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for DataSetGroup {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for DataSetGroup {
    fn namespace_skip(&self) -> usize {
        2
    }
}

impl Resolve<DataSetGroupResolved> for DataSetGroup {
    fn resolved_ref_cell(&self) -> &RefCell<Option<DataSetGroupResolved>> {
        &self.resolved
    }
}

#[derive(Debug)]
pub struct DataSetRecordResolved {
    pub value: Value,
}

#[derive(Debug)]
pub struct DataSetRecord {
    pub span: Span,
    pub path: Vec<usize>,
    pub string_path: Vec<String>,
    pub define_availability: Availability,
    pub actual_availability: RefCell<Availability>,
    pub identifier: Identifier,
    pub dictionary: DictionaryLiteral,
    pub resolved: RefCell<Option<DataSetRecordResolved>>,
}

impl Identifiable for DataSetRecord {
    fn path(&self) -> &Vec<usize> {
        &self.path
    }
}

impl NamedIdentifiable for DataSetRecord {
    fn string_path(&self) -> &Vec<String> {
        &self.string_path
    }
}

impl HasAvailability for DataSetRecord {
    fn define_availability(&self) -> Availability {
        self.define_availability
    }

    fn actual_availability(&self) -> Availability {
        *self.actual_availability.borrow()
    }
}

impl InfoProvider for DataSetRecord {
    fn namespace_skip(&self) -> usize {
        3
    }
}

impl Resolve<DataSetRecordResolved> for DataSetRecord {
    fn resolved_ref_cell(&self) -> &RefCell<Option<DataSetRecordResolved>> {
        &self.resolved
    }
}