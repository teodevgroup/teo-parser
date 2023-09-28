use std::fmt::{Display, Formatter};
use crate::ast::span::Span;
use crate::ast::unit::Unit;

#[derive(Debug)]
pub(crate) struct Pipeline {
    pub(crate) unit: Box<Unit>,
    pub(crate) span: Span,
}

impl Display for Pipeline {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("$")?;
        Display::fmt(&self.unit, f)
    }
}
