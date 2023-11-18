use crate::traits::has_availability::HasAvailability;
use crate::traits::identifiable::Identifiable;
use crate::traits::named_identifiable::NamedIdentifiable;

pub trait InfoProvider: Identifiable + NamedIdentifiable + HasAvailability {

    fn namespace_skip(&self) -> usize;

    fn namespace_str_path(&self) -> Vec<&str> {
        self.string_path().iter().rev().skip(self.namespace_skip()).rev().map(AsRef::as_ref).collect()
    }

    fn namespace_path(&self) -> Vec<usize> {
        self.path().iter().rev().skip(self.namespace_skip()).rev().collect()
    }
}