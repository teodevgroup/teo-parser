use std::fmt::{Display, Formatter};
use educe::Educe;
use serde::Serialize;

#[derive(Debug, Clone, Eq, Serialize)]
#[derive(Educe)]
#[educe(Hash, PartialEq)]
pub enum ShapeReference {
    BoolFilter,
    BoolNullableFilter,
    IntFilter,
    IntNullableFilter,
    Int64Filter,
    Int64NullableFilter,
    Float32Filter,
    Float32NullableFilter,
    FloatFilter,
    FloatNullableFilter,
    DecimalFilter,
    DecimalNullableFilter,
    DateFilter,
    DateNullableFilter,
    DateTimeFilter,
    DateTimeNullableFilter,
    ObjectIdFilter,
    ObjectIdNullableFilter,
    StringFilter,
    StringNullableFilter,
    Args(Vec<usize>, Vec<String>),
    FindManyArgs(Vec<usize>, Vec<String>),
}

impl Display for ShapeReference {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ShapeReference::BoolFilter => f.write_str("BoolFilter"),
            ShapeReference::BoolNullableFilter => f.write_str("BoolNullableFilter"),
            ShapeReference::IntFilter => f.write_str("IntFilter"),
            ShapeReference::IntNullableFilter => f.write_str("IntNullableFilter"),
            ShapeReference::Int64Filter => f.write_str("Int64Filter"),
            ShapeReference::Int64NullableFilter => f.write_str("Int64NullableFilter"),
            ShapeReference::Float32Filter => f.write_str("Float32Filter"),
            ShapeReference::Float32NullableFilter => f.write_str("Float32NullableFilter"),
            ShapeReference::FloatFilter => f.write_str("FloatFilter"),
            ShapeReference::FloatNullableFilter => f.write_str("FloatNullableFilter"),
            ShapeReference::DecimalFilter => f.write_str("DecimalFilter"),
            ShapeReference::DecimalNullableFilter => f.write_str("DecimalNullableFilter"),
            ShapeReference::DateFilter => f.write_str("DateFilter"),
            ShapeReference::DateNullableFilter => f.write_str("DateNullableFilter"),
            ShapeReference::DateTimeFilter => f.write_str("DateTimeFilter"),
            ShapeReference::DateTimeNullableFilter => f.write_str("DateTimeNullableFilter"),
            ShapeReference::ObjectIdFilter => f.write_str("ObjectIdFilter"),
            ShapeReference::ObjectIdNullableFilter => f.write_str("ObjectIdNullableFilter"),
            ShapeReference::StringFilter => f.write_str("StringFilter"),
            ShapeReference::StringNullableFilter => f.write_str("StringNullableFilter"),
            ShapeReference::Args(_, k) => f.write_str(&format!("Args<{}>", k.join("."))),
            ShapeReference::FindManyArgs(_, k) => f.write_str(&format!("FindManyArgs<{}>", k.join("."))),
        }
    }
}