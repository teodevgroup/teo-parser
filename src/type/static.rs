use indexmap::{IndexMap, indexmap};
use once_cell::sync::Lazy;
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::r#type::synthesized_shape_reference::SynthesizedShapeReference;
use crate::r#type::Type;

pub static STATIC_WHERE_INPUT_FOR_TYPE: Lazy<IndexMap<Type, Type>> = Lazy::new(|| {
    let mut result = indexmap! {};
    result.insert(Type::Bool, Type::Union(vec![Type::Bool, Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolFilter)]).wrap_in_optional());
    result.insert(Type::Bool.wrap_in_optional(), Type::Union(vec![Type::Bool, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolNullableFilter)]).wrap_in_optional());
    result.insert(Type::Int, Type::Union(vec![Type::Int, Type::SynthesizedShapeReference(SynthesizedShapeReference::IntFilter)]).wrap_in_optional());
    result.insert(Type::Int.wrap_in_optional(), Type::Union(vec![Type::Int, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::IntNullableFilter)]).wrap_in_optional());
    result.insert(Type::Int64, Type::Union(vec![Type::Int64, Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter)]).wrap_in_optional());
    result.insert(Type::Int64.wrap_in_optional(), Type::Union(vec![Type::Int64, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64NullableFilter)]).wrap_in_optional());
    result.insert(Type::Float32, Type::Union(vec![Type::Float32, Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32Filter)]).wrap_in_optional());
    result.insert(Type::Float32.wrap_in_optional(), Type::Union(vec![Type::Float32, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32NullableFilter)]).wrap_in_optional());
    result.insert(Type::Float, Type::Union(vec![Type::Float, Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatFilter)]).wrap_in_optional());
    result.insert(Type::Float.wrap_in_optional(), Type::Union(vec![Type::Float, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableFilter)]).wrap_in_optional());
    result.insert(Type::Decimal, Type::Union(vec![Type::Decimal, Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalFilter)]).wrap_in_optional());
    result.insert(Type::Decimal.wrap_in_optional(), Type::Union(vec![Type::Decimal, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalNullableFilter)]).wrap_in_optional());
    result.insert(Type::Date, Type::Union(vec![Type::Date, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateFilter)]).wrap_in_optional());
    result.insert(Type::Date.wrap_in_optional(), Type::Union(vec![Type::Date, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateNullableFilter)]).wrap_in_optional());
    result.insert(Type::DateTime, Type::Union(vec![Type::DateTime, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeFilter)]).wrap_in_optional());
    result.insert(Type::DateTime.wrap_in_optional(), Type::Union(vec![Type::DateTime, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeNullableFilter)]).wrap_in_optional());
    result.insert(Type::ObjectId, Type::Union(vec![Type::ObjectId, Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdFilter)]).wrap_in_optional());
    result.insert(Type::ObjectId.wrap_in_optional(), Type::Union(vec![Type::ObjectId, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdNullableFilter)]).wrap_in_optional());
    result.insert(Type::String, Type::Union(vec![Type::String, Type::SynthesizedShapeReference(SynthesizedShapeReference::StringFilter)]).wrap_in_optional());
    result.insert(Type::String.wrap_in_optional(), Type::Union(vec![Type::String, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::StringNullableFilter)]).wrap_in_optional());
    result
});

pub static STATIC_WHERE_WITH_AGGREGATES_INPUT_FOR_TYPE: Lazy<IndexMap<Type, Type>> = Lazy::new(|| {
    let mut result = indexmap! {};
    result.insert(Type::Bool, Type::Union(vec![Type::Bool, Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Bool.wrap_in_optional(), Type::Union(vec![Type::Bool, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolNullableWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Int, Type::Union(vec![Type::Int, Type::SynthesizedShapeReference(SynthesizedShapeReference::IntWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Int.wrap_in_optional(), Type::Union(vec![Type::Int, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::IntNullableWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Int64, Type::Union(vec![Type::Int64, Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64WithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Int64.wrap_in_optional(), Type::Union(vec![Type::Int64, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64NullableWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Float32, Type::Union(vec![Type::Float32, Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32WithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Float32.wrap_in_optional(), Type::Union(vec![Type::Float32, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32NullableWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Float, Type::Union(vec![Type::Float, Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Float.wrap_in_optional(), Type::Union(vec![Type::Float, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Decimal, Type::Union(vec![Type::Decimal, Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Decimal.wrap_in_optional(), Type::Union(vec![Type::Decimal, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalNullableWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Date, Type::Union(vec![Type::Date, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::Date.wrap_in_optional(), Type::Union(vec![Type::Date, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateNullableWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::DateTime, Type::Union(vec![Type::DateTime, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::DateTime.wrap_in_optional(), Type::Union(vec![Type::DateTime, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeNullableWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::ObjectId, Type::Union(vec![Type::ObjectId, Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::ObjectId.wrap_in_optional(), Type::Union(vec![Type::ObjectId, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdNullableWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::String, Type::Union(vec![Type::String, Type::SynthesizedShapeReference(SynthesizedShapeReference::StringWithAggregatesFilter)]).wrap_in_optional());
    result.insert(Type::String.wrap_in_optional(), Type::Union(vec![Type::String, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::StringNullableWithAggregatesFilter)]).wrap_in_optional());
    result
});

pub static STATIC_UPDATE_INPUT_FOR_TYPE: Lazy<IndexMap<Type, Type>> = Lazy::new(|| {
    let mut result = indexmap! {};
    result.insert(Type::Int, Type::Union(vec![Type::Int, Type::SynthesizedShapeReference(SynthesizedShapeReference::IntAtomicUpdateOperationInput)]).wrap_in_optional());
    result.insert(Type::Int.wrap_in_optional(), Type::Union(vec![Type::Int, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::IntAtomicUpdateOperationInput)]).wrap_in_optional());
    result.insert(Type::Int64, Type::Union(vec![Type::Int64, Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64AtomicUpdateOperationInput)]).wrap_in_optional());
    result.insert(Type::Int64.wrap_in_optional(), Type::Union(vec![Type::Int64, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64AtomicUpdateOperationInput)]).wrap_in_optional());
    result.insert(Type::Float32, Type::Union(vec![Type::Float32, Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32AtomicUpdateOperationInput)]).wrap_in_optional());
    result.insert(Type::Float32.wrap_in_optional(), Type::Union(vec![Type::Float32, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32AtomicUpdateOperationInput)]).wrap_in_optional());
    result.insert(Type::Float, Type::Union(vec![Type::Float, Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatAtomicUpdateOperationInput)]).wrap_in_optional());
    result.insert(Type::Float.wrap_in_optional(), Type::Union(vec![Type::Float, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatAtomicUpdateOperationInput)]).wrap_in_optional());
    result.insert(Type::Decimal, Type::Union(vec![Type::Decimal, Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalAtomicUpdateOperationInput)]).wrap_in_optional());
    result.insert(Type::Decimal.wrap_in_optional(), Type::Union(vec![Type::Decimal, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalAtomicUpdateOperationInput)]).wrap_in_optional());
    result
});