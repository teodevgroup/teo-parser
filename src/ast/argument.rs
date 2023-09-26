use std::fmt::{Display, Formatter};
use std::ops::Deref;
use teo_teon::value::Value;
use crate::ast::accessible::Accessible;
use crate::ast::expr::Expression;
use crate::ast::identifier::Identifier;
use crate::ast::span::Span;

#[derive(Debug)]
pub struct Argument {
    pub(crate) name: Option<Identifier>,
    pub(crate) value: Expression,
    pub(crate) span: Span,
}

impl Argument {

    pub fn get_value(&self) -> &Value {
        let r = unsafe { &*self.value.resolved.as_ptr() };
        r.as_ref().unwrap().as_value().unwrap()
    }
}

impl Display for Argument {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = &self.name {
            f.write_str(&name.name)?;
            f.write_str(": ")?;
        }
        Display::fmt(&self.value, f)
    }
}