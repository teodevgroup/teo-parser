use indexmap::{IndexMap, indexmap};
use once_cell::sync::Lazy;
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::r#type::synthesized_shape_reference::SynthesizedShapeReference;
use crate::r#type::Type;

pub static STATIC_TYPES: Lazy<IndexMap<String, Type>> = Lazy::new(|| {
    let mut result = indexmap! {};
    // bool filter
    let mut bool_filter_map = indexmap! {};
    bool_filter_map.insert("equals".to_owned(), Type::Bool.wrap_in_optional());
    bool_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Bool, Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolFilter)]).wrap_in_optional());
    result.insert("BoolFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(bool_filter_map.clone())));
    // bool nullable filter
    let mut bool_nullable_filter_map = indexmap! {};
    bool_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::Bool, Type::Null]).wrap_in_optional());
    bool_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Bool, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolNullableFilter)]).wrap_in_optional());
    result.insert("BoolNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(bool_nullable_filter_map.clone())));
    // int filter
    let mut int_filter_map = indexmap! {};
    int_filter_map.insert("equals".to_owned(), Type::Int.wrap_in_optional());
    int_filter_map.insert("in".to_owned(), Type::Int.wrap_in_array().wrap_in_optional());
    int_filter_map.insert("notIn".to_owned(), Type::Int.wrap_in_array().wrap_in_optional());
    int_filter_map.insert("lt".to_owned(), Type::Int.wrap_in_optional());
    int_filter_map.insert("lte".to_owned(), Type::Int.wrap_in_optional());
    int_filter_map.insert("gt".to_owned(), Type::Int.wrap_in_optional());
    int_filter_map.insert("gte".to_owned(), Type::Int.wrap_in_optional());
    int_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Int, Type::SynthesizedShapeReference(SynthesizedShapeReference::IntFilter)]).wrap_in_optional());
    result.insert("IntFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_filter_map.clone())));
    // int nullable filter
    let mut int_nullable_filter_map = indexmap! {};
    int_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::Int, Type::Null]).wrap_in_optional());
    int_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::Int, Type::Null]).wrap_in_array().wrap_in_optional());
    int_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::Int, Type::Null]).wrap_in_array().wrap_in_optional());
    int_nullable_filter_map.insert("lt".to_owned(), Type::Int.wrap_in_optional());
    int_nullable_filter_map.insert("lte".to_owned(), Type::Int.wrap_in_optional());
    int_nullable_filter_map.insert("gt".to_owned(), Type::Int.wrap_in_optional());
    int_nullable_filter_map.insert("gte".to_owned(), Type::Int.wrap_in_optional());
    int_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Int, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::IntNullableFilter)]).wrap_in_optional());
    result.insert("IntNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_nullable_filter_map.clone())));
    // int64 filter
    let mut int_64_filter_map = indexmap! {};
    int_64_filter_map.insert("equals".to_owned(), Type::Int64.wrap_in_optional());
    int_64_filter_map.insert("in".to_owned(), Type::Int64.wrap_in_array().wrap_in_optional());
    int_64_filter_map.insert("notIn".to_owned(), Type::Int64.wrap_in_array().wrap_in_optional());
    int_64_filter_map.insert("lt".to_owned(), Type::Int64.wrap_in_optional());
    int_64_filter_map.insert("lte".to_owned(), Type::Int64.wrap_in_optional());
    int_64_filter_map.insert("gt".to_owned(), Type::Int64.wrap_in_optional());
    int_64_filter_map.insert("gte".to_owned(), Type::Int64.wrap_in_optional());
    int_64_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Int64, Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter)]).wrap_in_optional());
    result.insert("Int64Filter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_64_filter_map.clone())));
    // int64 nullable filter
    let mut int_64_nullable_filter_map = indexmap! {};
    int_64_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::Int64, Type::Null]).wrap_in_optional());
    int_64_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::Int64, Type::Null]).wrap_in_array().wrap_in_optional());
    int_64_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::Int64, Type::Null]).wrap_in_array().wrap_in_optional());
    int_64_nullable_filter_map.insert("lt".to_owned(), Type::Int64.wrap_in_optional());
    int_64_nullable_filter_map.insert("lte".to_owned(), Type::Int64.wrap_in_optional());
    int_64_nullable_filter_map.insert("gt".to_owned(), Type::Int64.wrap_in_optional());
    int_64_nullable_filter_map.insert("gte".to_owned(), Type::Int64.wrap_in_optional());
    int_64_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Int64, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64NullableFilter)]).wrap_in_optional());
    result.insert("Int64NullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_64_nullable_filter_map.clone())));
    // float32 filter
    let mut float_32_filter_map = indexmap! {};
    float_32_filter_map.insert("equals".to_owned(), Type::Float32.wrap_in_optional());
    float_32_filter_map.insert("in".to_owned(), Type::Float32.wrap_in_array().wrap_in_optional());
    float_32_filter_map.insert("notIn".to_owned(), Type::Float32.wrap_in_array().wrap_in_optional());
    float_32_filter_map.insert("lt".to_owned(), Type::Float32.wrap_in_optional());
    float_32_filter_map.insert("lte".to_owned(), Type::Float32.wrap_in_optional());
    float_32_filter_map.insert("gt".to_owned(), Type::Float32.wrap_in_optional());
    float_32_filter_map.insert("gte".to_owned(), Type::Float32.wrap_in_optional());
    float_32_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Float32, Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32Filter)]).wrap_in_optional());
    result.insert("Float32Filter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_32_filter_map.clone())));
    // float32 nullable filter
    let mut float_32_nullable_filter_map = indexmap! {};
    float_32_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::Float32, Type::Null]).wrap_in_optional());
    float_32_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::Float32, Type::Null]).wrap_in_array().wrap_in_optional());
    float_32_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::Float32, Type::Null]).wrap_in_array().wrap_in_optional());
    float_32_nullable_filter_map.insert("lt".to_owned(), Type::Float32.wrap_in_optional());
    float_32_nullable_filter_map.insert("lte".to_owned(), Type::Float32.wrap_in_optional());
    float_32_nullable_filter_map.insert("gt".to_owned(), Type::Float32.wrap_in_optional());
    float_32_nullable_filter_map.insert("gte".to_owned(), Type::Float32.wrap_in_optional());
    float_32_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Float32, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32NullableFilter)]).wrap_in_optional());
    result.insert("Float32NullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_32_nullable_filter_map.clone())));
    // float filter
    let mut float_filter_map = indexmap! {};
    float_filter_map.insert("equals".to_owned(), Type::Float.wrap_in_optional());
    float_filter_map.insert("in".to_owned(), Type::Float.wrap_in_array().wrap_in_optional());
    float_filter_map.insert("notIn".to_owned(), Type::Float.wrap_in_array().wrap_in_optional());
    float_filter_map.insert("lt".to_owned(), Type::Float.wrap_in_optional());
    float_filter_map.insert("lte".to_owned(), Type::Float.wrap_in_optional());
    float_filter_map.insert("gt".to_owned(), Type::Float.wrap_in_optional());
    float_filter_map.insert("gte".to_owned(), Type::Float.wrap_in_optional());
    float_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Float, Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatFilter)]).wrap_in_optional());
    result.insert("FloatFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_filter_map.clone())));
    // float nullable filter
    let mut float_nullable_filter_map = indexmap! {};
    float_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::Float, Type::Null]).wrap_in_optional());
    float_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::Float, Type::Null]).wrap_in_array().wrap_in_optional());
    float_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::Float, Type::Null]).wrap_in_array().wrap_in_optional());
    float_nullable_filter_map.insert("lt".to_owned(), Type::Float.wrap_in_optional());
    float_nullable_filter_map.insert("lte".to_owned(), Type::Float.wrap_in_optional());
    float_nullable_filter_map.insert("gt".to_owned(), Type::Float.wrap_in_optional());
    float_nullable_filter_map.insert("gte".to_owned(), Type::Float.wrap_in_optional());
    float_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Float, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableFilter)]).wrap_in_optional());
    result.insert("FloatNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_nullable_filter_map.clone())));
    // decimal filter
    let mut decimal_filter_map = indexmap! {};
    decimal_filter_map.insert("equals".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_filter_map.insert("in".to_owned(), Type::Decimal.wrap_in_array().wrap_in_optional());
    decimal_filter_map.insert("notIn".to_owned(), Type::Decimal.wrap_in_array().wrap_in_optional());
    decimal_filter_map.insert("lt".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_filter_map.insert("lte".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_filter_map.insert("gt".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_filter_map.insert("gte".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Decimal, Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalFilter)]).wrap_in_optional());
    result.insert("DecimalFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(decimal_filter_map.clone())));
    // decimal nullable filter
    let mut decimal_nullable_filter_map = indexmap! {};
    decimal_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::Decimal, Type::Null]).wrap_in_optional());
    decimal_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::Decimal, Type::Null]).wrap_in_array().wrap_in_optional());
    decimal_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::Decimal, Type::Null]).wrap_in_array().wrap_in_optional());
    decimal_nullable_filter_map.insert("lt".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_nullable_filter_map.insert("lte".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_nullable_filter_map.insert("gt".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_nullable_filter_map.insert("gte".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Decimal, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalNullableFilter)]).wrap_in_optional());
    result.insert("DecimalNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(decimal_nullable_filter_map.clone())));
    // date filter
    let mut date_filter_map = indexmap! {};
    date_filter_map.insert("equals".to_owned(), Type::Date.wrap_in_optional());
    date_filter_map.insert("in".to_owned(), Type::Date.wrap_in_array().wrap_in_optional());
    date_filter_map.insert("notIn".to_owned(), Type::Date.wrap_in_array().wrap_in_optional());
    date_filter_map.insert("lt".to_owned(), Type::Date.wrap_in_optional());
    date_filter_map.insert("lte".to_owned(), Type::Date.wrap_in_optional());
    date_filter_map.insert("gt".to_owned(), Type::Date.wrap_in_optional());
    date_filter_map.insert("gte".to_owned(), Type::Date.wrap_in_optional());
    date_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Date, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateFilter)]).wrap_in_optional());
    result.insert("DateFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(date_filter_map.clone())));
    // date nullable filter
    let mut date_nullable_filter_map = indexmap! {};
    date_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::Date, Type::Null]).wrap_in_optional());
    date_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::Date, Type::Null]).wrap_in_array().wrap_in_optional());
    date_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::Date, Type::Null]).wrap_in_array().wrap_in_optional());
    date_nullable_filter_map.insert("lt".to_owned(), Type::Date.wrap_in_optional());
    date_nullable_filter_map.insert("lte".to_owned(), Type::Date.wrap_in_optional());
    date_nullable_filter_map.insert("gt".to_owned(), Type::Date.wrap_in_optional());
    date_nullable_filter_map.insert("gte".to_owned(), Type::Date.wrap_in_optional());
    date_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::Date, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateNullableFilter)]).wrap_in_optional());
    result.insert("DateNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(date_nullable_filter_map.clone())));
    // datetime filter
    let mut datetime_filter_map = indexmap! {};
    datetime_filter_map.insert("equals".to_owned(), Type::DateTime.wrap_in_optional());
    datetime_filter_map.insert("in".to_owned(), Type::DateTime.wrap_in_array().wrap_in_optional());
    datetime_filter_map.insert("notIn".to_owned(), Type::DateTime.wrap_in_array().wrap_in_optional());
    datetime_filter_map.insert("lt".to_owned(), Type::DateTime.wrap_in_optional());
    datetime_filter_map.insert("lte".to_owned(), Type::DateTime.wrap_in_optional());
    datetime_filter_map.insert("gt".to_owned(), Type::DateTime.wrap_in_optional());
    datetime_filter_map.insert("gte".to_owned(), Type::DateTime.wrap_in_optional());
    datetime_filter_map.insert("not".to_owned(), Type::Union(vec![Type::DateTime, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeFilter)]).wrap_in_optional());
    result.insert("DateTimeFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(datetime_filter_map.clone())));
    // datetime nullable filter
    let mut datetime_nullable_filter_map = indexmap! {};
    datetime_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::DateTime, Type::Null]).wrap_in_optional());
    datetime_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::DateTime, Type::Null]).wrap_in_array().wrap_in_optional());
    datetime_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::DateTime, Type::Null]).wrap_in_array().wrap_in_optional());
    datetime_nullable_filter_map.insert("lt".to_owned(), Type::DateTime.wrap_in_optional());
    datetime_nullable_filter_map.insert("lte".to_owned(), Type::DateTime.wrap_in_optional());
    datetime_nullable_filter_map.insert("gt".to_owned(), Type::DateTime.wrap_in_optional());
    datetime_nullable_filter_map.insert("gte".to_owned(), Type::DateTime.wrap_in_optional());
    datetime_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::DateTime, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeNullableFilter)]).wrap_in_optional());
    result.insert("DateTimeNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(datetime_nullable_filter_map.clone())));
    // object id filter
    let mut object_id_filter_map = indexmap! {};
    object_id_filter_map.insert("equals".to_owned(), Type::ObjectId.wrap_in_optional());
    object_id_filter_map.insert("in".to_owned(), Type::ObjectId.wrap_in_array().wrap_in_optional());
    object_id_filter_map.insert("notIn".to_owned(), Type::ObjectId.wrap_in_array().wrap_in_optional());
    object_id_filter_map.insert("lt".to_owned(), Type::ObjectId.wrap_in_optional());
    object_id_filter_map.insert("lte".to_owned(), Type::ObjectId.wrap_in_optional());
    object_id_filter_map.insert("gt".to_owned(), Type::ObjectId.wrap_in_optional());
    object_id_filter_map.insert("gte".to_owned(), Type::ObjectId.wrap_in_optional());
    object_id_filter_map.insert("not".to_owned(), Type::Union(vec![Type::ObjectId, Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdFilter)]).wrap_in_optional());
    result.insert("ObjectIdFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(object_id_filter_map.clone())));
    // object id nullable filter
    let mut object_id_nullable_filter_map = indexmap! {};
    object_id_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::ObjectId, Type::Null]).wrap_in_optional());
    object_id_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::ObjectId, Type::Null]).wrap_in_array().wrap_in_optional());
    object_id_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::ObjectId, Type::Null]).wrap_in_array().wrap_in_optional());
    object_id_nullable_filter_map.insert("lt".to_owned(), Type::ObjectId.wrap_in_optional());
    object_id_nullable_filter_map.insert("lte".to_owned(), Type::ObjectId.wrap_in_optional());
    object_id_nullable_filter_map.insert("gt".to_owned(), Type::ObjectId.wrap_in_optional());
    object_id_nullable_filter_map.insert("gte".to_owned(), Type::ObjectId.wrap_in_optional());
    object_id_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::ObjectId, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdNullableFilter)]).wrap_in_optional());
    result.insert("ObjectIdNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(object_id_nullable_filter_map.clone())));
    // string filter
    let mut string_filter_map = indexmap! {};
    string_filter_map.insert("equals".to_owned(), Type::String.wrap_in_optional());
    string_filter_map.insert("in".to_owned(), Type::String.wrap_in_array().wrap_in_optional());
    string_filter_map.insert("notIn".to_owned(), Type::String.wrap_in_array().wrap_in_optional());
    string_filter_map.insert("lt".to_owned(), Type::String.wrap_in_optional());
    string_filter_map.insert("lte".to_owned(), Type::String.wrap_in_optional());
    string_filter_map.insert("gt".to_owned(), Type::String.wrap_in_optional());
    string_filter_map.insert("gte".to_owned(), Type::String.wrap_in_optional());
    string_filter_map.insert("contains".to_owned(), Type::String.wrap_in_optional());
    string_filter_map.insert("startsWith".to_owned(), Type::String.wrap_in_optional());
    string_filter_map.insert("endsWith".to_owned(), Type::String.wrap_in_optional());
    string_filter_map.insert("matches".to_owned(), Type::String.wrap_in_optional());
    string_filter_map.insert("not".to_owned(), Type::Union(vec![Type::String, Type::SynthesizedShapeReference(SynthesizedShapeReference::StringFilter)]).wrap_in_optional());
    result.insert("StringFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(string_filter_map.clone())));
    // string nullable filter
    let mut string_nullable_filter_map = indexmap! {};
    string_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::String, Type::Null]).wrap_in_optional());
    string_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::String, Type::Null]).wrap_in_array().wrap_in_optional());
    string_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::String, Type::Null]).wrap_in_array().wrap_in_optional());
    string_nullable_filter_map.insert("lt".to_owned(), Type::String.wrap_in_optional());
    string_nullable_filter_map.insert("lte".to_owned(), Type::String.wrap_in_optional());
    string_nullable_filter_map.insert("gt".to_owned(), Type::String.wrap_in_optional());
    string_nullable_filter_map.insert("gte".to_owned(), Type::String.wrap_in_optional());
    string_nullable_filter_map.insert("contains".to_owned(), Type::String.wrap_in_optional());
    string_nullable_filter_map.insert("startsWith".to_owned(), Type::String.wrap_in_optional());
    string_nullable_filter_map.insert("endsWith".to_owned(), Type::String.wrap_in_optional());
    string_nullable_filter_map.insert("matches".to_owned(), Type::String.wrap_in_optional());
    string_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::String, Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::StringNullableFilter)]).wrap_in_optional());
    result.insert("StringNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(string_nullable_filter_map.clone())));
    // enum filter
    let mut enum_filter_map = indexmap! {};
    enum_filter_map.insert("equals".to_owned(), Type::GenericItem("T".to_string()).wrap_in_optional());
    enum_filter_map.insert("in".to_owned(), Type::GenericItem("T".to_string()).wrap_in_array().wrap_in_optional());
    enum_filter_map.insert("notIn".to_owned(), Type::GenericItem("T".to_string()).wrap_in_array().wrap_in_optional());
    enum_filter_map.insert("not".to_owned(), Type::Union(vec![Type::GenericItem("T".to_string()), Type::SynthesizedShapeReference(SynthesizedShapeReference::EnumFilter(Box::new(Type::GenericItem("T".to_string()))))]).wrap_in_optional());
    result.insert("EnumFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(enum_filter_map.clone())));
    // enum nullable filter
    let mut enum_nullable_filter_map = indexmap! {};
    enum_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::GenericItem("T".to_string()), Type::Null]).wrap_in_optional());
    enum_nullable_filter_map.insert("in".to_owned(), Type::Union(vec![Type::GenericItem("T".to_string()), Type::Null]).wrap_in_array().wrap_in_optional());
    enum_nullable_filter_map.insert("notIn".to_owned(), Type::Union(vec![Type::GenericItem("T".to_string()), Type::Null]).wrap_in_array().wrap_in_optional());
    enum_nullable_filter_map.insert("not".to_owned(), Type::Union(vec![Type::GenericItem("T".to_string()), Type::Null, Type::SynthesizedShapeReference(SynthesizedShapeReference::EnumNullableFilter(Box::new(Type::GenericItem("T".to_string()))))]).wrap_in_optional());
    result.insert("EnumNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(enum_nullable_filter_map.clone())));
    // array filter
    let mut array_filter_map = indexmap! {};
    array_filter_map.insert("equals".to_owned(), Type::GenericItem("T".to_string()).wrap_in_array().wrap_in_optional());
    array_filter_map.insert("has".to_owned(), Type::GenericItem("T".to_string()).wrap_in_optional());
    array_filter_map.insert("hasSome".to_owned(), Type::GenericItem("T".to_string()).wrap_in_array().wrap_in_optional());
    array_filter_map.insert("hasEvery".to_owned(), Type::GenericItem("T".to_string()).wrap_in_array().wrap_in_optional());
    array_filter_map.insert("isEmpty".to_owned(), Type::Bool.wrap_in_optional());
    array_filter_map.insert("length".to_owned(), Type::Int.wrap_in_optional());
    result.insert("ArrayFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(array_filter_map.clone())));
    // array nullable filter
    let mut array_nullable_filter_map = indexmap! {};
    array_nullable_filter_map.insert("equals".to_owned(), Type::Union(vec![Type::GenericItem("T".to_string()).wrap_in_array(), Type::Null]).wrap_in_optional());
    array_nullable_filter_map.insert("has".to_owned(), Type::GenericItem("T".to_string()).wrap_in_optional());
    array_nullable_filter_map.insert("hasSome".to_owned(), Type::GenericItem("T".to_string()).wrap_in_array().wrap_in_optional());
    array_nullable_filter_map.insert("hasEvery".to_owned(), Type::GenericItem("T".to_string()).wrap_in_array().wrap_in_optional());
    array_nullable_filter_map.insert("isEmpty".to_owned(), Type::Bool.wrap_in_optional());
    array_nullable_filter_map.insert("length".to_owned(), Type::Int.wrap_in_optional());
    result.insert("ArrayNullableFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(array_nullable_filter_map.clone())));

    // bool with aggregates filter
    bool_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    bool_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolFilter).wrap_in_optional());
    bool_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolFilter).wrap_in_optional());
    result.insert("BoolWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(bool_filter_map)));
    // bool nullable with aggregates filter
    bool_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    bool_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolNullableFilter).wrap_in_optional());
    bool_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::BoolNullableFilter).wrap_in_optional());
    result.insert("BoolWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(bool_nullable_filter_map)));
    // int with aggregates filter
    int_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    int_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::IntFilter).wrap_in_optional());
    int_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::IntFilter).wrap_in_optional());
    int_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatFilter).wrap_in_optional());
    int_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    result.insert("IntWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_filter_map)));
    // int nullable with aggregates filter
    int_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    int_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::IntNullableFilter).wrap_in_optional());
    int_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::IntNullableFilter).wrap_in_optional());
    int_nullable_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableFilter).wrap_in_optional());
    int_nullable_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64NullableFilter).wrap_in_optional());
    result.insert("IntNullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_nullable_filter_map)));
    // int 64 with aggregates filter
    int_64_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    int_64_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    int_64_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    int_64_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatFilter).wrap_in_optional());
    int_64_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    result.insert("Int64WithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_64_filter_map)));
    // int 64 nullable with aggregates filter
    int_64_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    int_64_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64NullableFilter).wrap_in_optional());
    int_64_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64NullableFilter).wrap_in_optional());
    int_64_nullable_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableFilter).wrap_in_optional());
    int_64_nullable_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64NullableFilter).wrap_in_optional());
    result.insert("Int64NullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_64_nullable_filter_map)));
    // float 32 with aggregates filter
    float_32_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    float_32_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32Filter).wrap_in_optional());
    float_32_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32Filter).wrap_in_optional());
    float_32_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32Filter).wrap_in_optional());
    float_32_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatFilter).wrap_in_optional());
    result.insert("Float32WithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_32_filter_map)));
    // float 32 nullable with aggregates filter
    float_32_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    float_32_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32NullableFilter).wrap_in_optional());
    float_32_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32NullableFilter).wrap_in_optional());
    float_32_nullable_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Float32NullableFilter).wrap_in_optional());
    float_32_nullable_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableFilter).wrap_in_optional());
    result.insert("Float32NullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_32_nullable_filter_map)));
    // float with aggregates filter
    float_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    float_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatFilter).wrap_in_optional());
    float_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatFilter).wrap_in_optional());
    float_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatFilter).wrap_in_optional());
    float_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatFilter).wrap_in_optional());
    result.insert("FloatWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_filter_map)));
    // float nullable with aggregates filter
    float_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    float_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableFilter).wrap_in_optional());
    float_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableFilter).wrap_in_optional());
    float_nullable_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableFilter).wrap_in_optional());
    float_nullable_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::FloatNullableFilter).wrap_in_optional());
    result.insert("FloatNullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_nullable_filter_map)));
    // decimal with aggregates filter
    decimal_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    decimal_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalFilter).wrap_in_optional());
    decimal_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalFilter).wrap_in_optional());
    decimal_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalFilter).wrap_in_optional());
    decimal_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalFilter).wrap_in_optional());
    result.insert("DecimalWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(decimal_filter_map)));
    // decimal nullable with aggregates filter
    decimal_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    decimal_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalNullableFilter).wrap_in_optional());
    decimal_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalNullableFilter).wrap_in_optional());
    decimal_nullable_filter_map.insert("_avg".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalNullableFilter).wrap_in_optional());
    decimal_nullable_filter_map.insert("_sum".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DecimalNullableFilter).wrap_in_optional());
    result.insert("DecimalNullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(decimal_nullable_filter_map)));
    // date with aggregates filter
    date_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    date_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DateFilter).wrap_in_optional());
    date_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DateFilter).wrap_in_optional());
    result.insert("DateWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(date_filter_map)));
    // date nullable with aggregates filter
    date_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    date_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DateNullableFilter).wrap_in_optional());
    date_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DateNullableFilter).wrap_in_optional());
    result.insert("DateNullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(date_nullable_filter_map)));
    // date time with aggregates filter
    datetime_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    datetime_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeFilter).wrap_in_optional());
    datetime_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeFilter).wrap_in_optional());
    result.insert("DateTimeWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(datetime_filter_map)));
    // date time nullable with aggregates filter
    datetime_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    datetime_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeNullableFilter).wrap_in_optional());
    datetime_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::DateTimeNullableFilter).wrap_in_optional());
    result.insert("DateTimeNullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(datetime_nullable_filter_map)));
    // object id with aggregates filter
    object_id_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    object_id_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdFilter).wrap_in_optional());
    object_id_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdFilter).wrap_in_optional());
    result.insert("ObjectIdWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(object_id_filter_map)));
    // object id nullable with aggregates filter
    object_id_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    object_id_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdNullableFilter).wrap_in_optional());
    object_id_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::ObjectIdNullableFilter).wrap_in_optional());
    result.insert("ObjectIdNullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(object_id_nullable_filter_map)));
    // string with aggregates filter
    string_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    string_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::StringFilter).wrap_in_optional());
    string_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::StringFilter).wrap_in_optional());
    result.insert("StringWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(string_filter_map)));
    // string nullable with aggregates filter
    string_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    string_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::StringNullableFilter).wrap_in_optional());
    string_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::StringNullableFilter).wrap_in_optional());
    result.insert("StringNullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(string_nullable_filter_map)));
    // enum with aggregates filter
    enum_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    enum_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::EnumFilter(Box::new(Type::GenericItem("T".to_owned())))).wrap_in_optional());
    enum_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::EnumFilter(Box::new(Type::GenericItem("T".to_owned())))).wrap_in_optional());
    result.insert("EnumWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(enum_filter_map)));
    // enum nullable with aggregates filter
    enum_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    enum_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::EnumNullableFilter(Box::new(Type::GenericItem("T".to_owned())))).wrap_in_optional());
    enum_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::EnumNullableFilter(Box::new(Type::GenericItem("T".to_owned())))).wrap_in_optional());
    result.insert("EnumNullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(enum_nullable_filter_map)));
    // array with aggregates filter
    array_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    array_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::ArrayFilter(Box::new(Type::GenericItem("T".to_owned())))).wrap_in_optional());
    array_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::ArrayFilter(Box::new(Type::GenericItem("T".to_owned())))).wrap_in_optional());
    result.insert("ArrayWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(array_filter_map)));
    // array nullable with aggregates filter
    array_nullable_filter_map.insert("_count".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::Int64Filter).wrap_in_optional());
    array_nullable_filter_map.insert("_min".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::ArrayNullableFilter(Box::new(Type::GenericItem("T".to_owned())))).wrap_in_optional());
    array_nullable_filter_map.insert("_max".to_owned(), Type::SynthesizedShapeReference(SynthesizedShapeReference::ArrayNullableFilter(Box::new(Type::GenericItem("T".to_owned())))).wrap_in_optional());
    result.insert("ArrayNullableWithAggregatesFilter".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(array_nullable_filter_map)));

    // int atomic update operation input
    let mut int_atomic_update_operation_input_map = indexmap! {};
    int_atomic_update_operation_input_map.insert("increment".to_owned(), Type::Int.wrap_in_optional());
    int_atomic_update_operation_input_map.insert("decrement".to_owned(), Type::Int.wrap_in_optional());
    int_atomic_update_operation_input_map.insert("multiply".to_owned(), Type::Int.wrap_in_optional());
    int_atomic_update_operation_input_map.insert("divide".to_owned(), Type::Int.wrap_in_optional());
    result.insert("IntAtomicUpdateOperationInput".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_atomic_update_operation_input_map)));
    // int64 atomic update operation input
    let mut int_64_atomic_update_operation_input_map = indexmap! {};
    int_64_atomic_update_operation_input_map.insert("increment".to_owned(), Type::Int64.wrap_in_optional());
    int_64_atomic_update_operation_input_map.insert("decrement".to_owned(), Type::Int64.wrap_in_optional());
    int_64_atomic_update_operation_input_map.insert("multiply".to_owned(), Type::Int64.wrap_in_optional());
    int_64_atomic_update_operation_input_map.insert("divide".to_owned(), Type::Int64.wrap_in_optional());
    result.insert("Int64AtomicUpdateOperationInput".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(int_64_atomic_update_operation_input_map)));
    // float32 atomic update operation input
    let mut float_32_atomic_update_operation_input_map = indexmap! {};
    float_32_atomic_update_operation_input_map.insert("increment".to_owned(), Type::Float32.wrap_in_optional());
    float_32_atomic_update_operation_input_map.insert("decrement".to_owned(), Type::Float32.wrap_in_optional());
    float_32_atomic_update_operation_input_map.insert("multiply".to_owned(), Type::Float32.wrap_in_optional());
    float_32_atomic_update_operation_input_map.insert("divide".to_owned(), Type::Float32.wrap_in_optional());
    result.insert("Float32AtomicUpdateOperationInput".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_32_atomic_update_operation_input_map)));
    // float atomic update operation input
    let mut float_atomic_update_operation_input_map = indexmap! {};
    float_atomic_update_operation_input_map.insert("increment".to_owned(), Type::Float.wrap_in_optional());
    float_atomic_update_operation_input_map.insert("decrement".to_owned(), Type::Float.wrap_in_optional());
    float_atomic_update_operation_input_map.insert("multiply".to_owned(), Type::Float.wrap_in_optional());
    float_atomic_update_operation_input_map.insert("divide".to_owned(), Type::Float.wrap_in_optional());
    result.insert("FloatAtomicUpdateOperationInput".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(float_atomic_update_operation_input_map)));
    // decimal atomic update operation input
    let mut decimal_atomic_update_operation_input_map = indexmap! {};
    decimal_atomic_update_operation_input_map.insert("increment".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_atomic_update_operation_input_map.insert("decrement".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_atomic_update_operation_input_map.insert("multiply".to_owned(), Type::Decimal.wrap_in_optional());
    decimal_atomic_update_operation_input_map.insert("divide".to_owned(), Type::Decimal.wrap_in_optional());
    result.insert("DecimalAtomicUpdateOperationInput".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(decimal_atomic_update_operation_input_map)));
    // array atomic update operation input
    let mut array_atomic_update_operation_input_map = indexmap! {};
    array_atomic_update_operation_input_map.insert("push".to_owned(), Type::GenericItem("T".to_owned()).wrap_in_optional());
    result.insert("ArrayAtomicUpdateOperationInput".to_owned(), Type::SynthesizedShape(SynthesizedShape::new(array_atomic_update_operation_input_map)));

    result
});

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