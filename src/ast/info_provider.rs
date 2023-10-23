use crate::ast::availability::Availability;
use crate::ast::identifiable::Identifiable;

pub trait InfoProvider: Identifiable {

    fn namespace_str_path(&self) -> Vec<&str>;

    fn availability(&self) -> Availability;
}