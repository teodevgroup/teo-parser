use crate::ast::availability::Availability;
use crate::ast::schema::Schema;
use crate::ast::source::Source;

pub trait InfoProvider {

    fn namespace_str_path(&self) -> Vec<&str>;

    fn availability(&self, schema: &Schema, source: &Source) -> Availability;
}