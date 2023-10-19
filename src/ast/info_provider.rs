use crate::ast::availability::Availability;

pub trait InfoProvider {

    fn namespace_str_path(&self) -> Vec<&str>;

    fn availability(&self) -> Availability;
}