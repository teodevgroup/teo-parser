use crate::ast::reference::ReferenceType;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::unit::Unit;
use crate::r#type::r#type::Type;
use crate::search::search_identifier_path::search_identifier_path_in_source;
use crate::utils::top_filter::top_filter_for_reference_type;

#[derive(Debug)]
pub enum UnitSearchResult {
    Type(Type),
    Reference(Vec<usize>),
}

impl UnitSearchResult {

    pub(super) fn is_reference(&self) -> bool {
        self.as_reference().is_some()
    }

    pub(super) fn as_reference(&self) -> Option<&Vec<usize>> {
        match self {
            Self::Reference(r) => Some(r),
            _ => None,
        }
    }

    pub(super) fn is_type(&self) -> bool {
        self.as_type().is_some()
    }

    pub(super) fn as_type(&self) -> Option<&Type> {
        match self {
            Self::Type(t) => Some(t),
            _ => None,
        }
    }
}

fn search_unit(
    schema: &Schema,
    source: &Source,
    unit: &Unit,
    namespace_path: &Vec<&str>,
    line_col: (usize, usize),
    expect: &Type,
) -> UnitSearchResult {
    let mut current = if let Some(identifier) = unit.expressions.get(0).unwrap().kind.as_identifier() {
        if let Some(path) = search_identifier_path_in_source(
            schema,
            source,
            namespace_path,
            &vec![identifier.name()],
            &top_filter_for_reference_type(ReferenceType::Default),
        ) {
            UnitSearchResult::Reference(path)
        } else {
            UnitSearchResult::Type(Type::Undetermined)
        }
    } else {
        unreachable!()
    };
    for expression in &unit.expressions {

        if expression.span().contains_line_col(line_col) {
            break
        }
    }
    current
}
