use std::fmt::{Display, Formatter};
use teo_teon::value::Value;
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
        self.value.resolved.lock().unwrap().as_ref().unwrap().as_value().unwrap()
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