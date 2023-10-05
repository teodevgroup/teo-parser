use teo_teon::value::Value;
use crate::ast::reference::Reference;

#[derive(Debug)]
pub(crate) enum Accessible {
    Value(Value),
    Reference(Reference),
}

impl Accessible {

    pub(crate) fn is_value(&self) -> bool {
        self.as_value().is_some()
    }

    pub(crate) fn as_value(&self) -> Option<&Value> {
        use Accessible::*;
        match self {
            Value(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn into_value(self) -> Option<Value> {
        use Accessible::*;
        match self {
            Value(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn is_reference(&self) -> bool {
        self.as_reference().is_some()
    }

    pub(crate) fn as_reference(&self) -> Option<&Reference> {
        use Accessible::*;
        match self {
            Reference(r) => Some(r),
            _ => None,
        }
    }

    pub(crate) fn into_reference(self) -> Option<Reference> {
        use Accessible::*;
        match self {
            Reference(r) => Some(r),
            _ => None,
        }
    }

    pub(crate) fn is_undetermined(&self) -> bool {
        self.is_value() && self.as_value().unwrap().is_undetermined()
    }
}