use indexmap::indexmap;
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

    pub fn is_or(&self) -> bool {
        self.as_or().is_some()
    }

    pub fn as_or(&self) -> Option<&Vec<Input>> {
        match self {
            Input::Or(s) => Some(s),
            _ => None,
        }
    }

    pub fn or_to_shape(&self) -> Shape {
        let mut result = Shape::new(indexmap! {});
        let mut times = 0;
        if self.is_or() {
            for input in self.as_or().unwrap() {
                if let Some(shape) = input.as_shape() {
                    result.extend(shape.clone().into_iter());
                    times += 1;
                }
            }
        }
        if times > 1 {
            result.iter_mut().for_each(|(_, input)| {
                if let Some(t) = input.as_type_mut() {
                    *t = t.to_optional();
                }
            })
        }
        result
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

    pub fn into_shape(self) -> Option<Shape> {
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

    pub fn as_type_mut(&mut self) -> Option<&mut Type> {
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

    pub fn is_optional(&self) -> bool {
        self.is_type() && self.as_type().unwrap().is_optional()
    }
}