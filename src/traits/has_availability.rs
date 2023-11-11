use crate::ast::availability::Availability;

pub trait HasAvailability {

    fn define_availability(&self) -> Availability;

    fn actual_availability(&self) -> Availability;

    fn availability(&self) -> Availability {
        self.define_availability().bi_and(self.actual_availability())
    }

    fn is_available(&self) -> bool {
        self.define_availability().contains(self.actual_availability())
    }
}