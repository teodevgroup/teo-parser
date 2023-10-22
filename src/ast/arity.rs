#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Arity {
    Scalar,
    Array,
    Dictionary,
}

impl Arity {

    pub fn is_scalar(&self) -> bool {
        use Arity::*;
        match self {
            Scalar => true,
            _ => false,
        }
    }

    pub fn is_array(&self) -> bool {
        use Arity::*;
        match self {
            Array => true,
            _ => false,
        }
    }

    pub fn is_dictionary(&self) -> bool {
        use Arity::*;
        match self {
            Dictionary => true,
            _ => false,
        }
    }
}