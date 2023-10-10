use teo_teon::value::Value;
use crate::ast::type_expr::Type;
use crate::ast::reference::Reference;

#[derive(Debug, Clone)]
pub(crate) enum Accessible {
    Type(Type),
    Reference(Reference),
}

impl Accessible {

    pub(crate) fn is_type(&self) -> bool {
        self.as_type().is_some()
    }

    pub(crate) fn as_type(&self) -> Option<&Type> {
        use Accessible::*;
        match self {
            Type(v) => Some(v),
            _ => None,
        }
    }

    pub(crate) fn into_type(self) -> Option<Type> {
        use Accessible::*;
        match self {
            Type(v) => Some(v),
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
        self.is_type() && self.as_type().unwrap().is_undetermined()
    }
}