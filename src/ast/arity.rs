#[derive(Debug, PartialEq, Copy, Clone)]
pub(crate) enum Arity {
    Scalar,
    Array,
    Dictionary,
}

impl Arity {

    pub(crate) fn is_scalar(&self) -> bool {
        use Arity::*;
        match self {
            Scalar => true,
            _ => false,
        }
    }

    pub(crate) fn is_array(&self) -> bool {
        use Arity::*;
        match self {
            Array => true,
            _ => false,
        }
    }

    pub(crate) fn is_dictionary(&self) -> bool {
        use Arity::*;
        match self {
            Dictionary => true,
            _ => false,
        }
    }
}