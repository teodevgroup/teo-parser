use serde::Serialize;
use crate::r#type::Type;
use crate::shape::shape::Shape;

#[derive(Debug, Serialize)]
pub enum Input {
    Undetermined,
    Shape(Shape),
    Type(Type),
    Enumerable(Box<Input>),
}

impl Input {

    pub fn is_undetermined(&self) -> bool {
        match self {
            Input::Undetermined => true,
            _ => false,
        }
    }

    pub fn is_shape(&self) -> bool {
        self.as_shape().is_some()
    }

    pub fn as_shape(&self) -> Option<&Shape> {
        match self {
            Input::Shape(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_type(&self) -> bool {
        self.as_type().is_some()
    }

    pub fn as_type(&self) -> Option<&Type> {
        match self {
            Input::Type(t) => Some(t),
            _ => None,
        }
    }

    pub fn is_enumerable(&self) -> bool {
        self.as_enumerable().is_some()
    }

    pub fn as_enumerable(&self) -> Option<&Input> {
        match self {
            Input::Enumerable(t) => Some(t.as_ref()),
            _ => None,
        }
    }
}