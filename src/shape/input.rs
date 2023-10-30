use serde::Serialize;
use crate::r#type::Type;
use crate::shape::shape::Shape;
use crate::shape::synthesized_enum::SynthesizedEnum;

#[derive(Debug, Serialize, Clone)]
pub enum Input {
    Undetermined,
    Or(Vec<Input>),
    Shape(Shape),
    Type(Type),
    SynthesizedEnum(SynthesizedEnum),
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

    pub fn is_synthesized_enum(&self) -> bool {
        self.as_synthesized_enum().is_some()
    }

    pub fn as_synthesized_enum(&self) -> Option<&SynthesizedEnum> {
        match self {
            Input::SynthesizedEnum(s) => Some(s),
            _ => None,
        }
    }
}