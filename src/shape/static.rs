use indexmap::{IndexMap, indexmap};
use once_cell::sync::Lazy;
use crate::r#type::shape_reference::ShapeReference;
use crate::r#type::Type;
use crate::shape::input::Input;
use crate::shape::shape::Shape;

pub(super) static STATIC_TYPES: Lazy<IndexMap<String, Input>> = Lazy::new(|| {
    let mut result = indexmap! {};
    // bool filter
    let mut bool_filter_map = indexmap! {};
    bool_filter_map.insert("equals".to_owned(), Input::Type(Type::Bool.to_optional()));
    bool_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Bool, Type::ShapeReference(ShapeReference::BoolFilter)]).to_optional()));
    result.insert("BoolFilter".to_owned(), Input::Shape(Shape::new(bool_filter_map)));
    // bool nullable filter
    let mut bool_nullable_filter_map = indexmap! {};
    bool_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::Bool, Type::Null]).to_optional()));
    bool_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Bool, Type::Null, Type::ShapeReference(ShapeReference::BoolNullableFilter)]).to_optional()));
    result.insert("BoolNullableFilter".to_owned(), Input::Shape(Shape::new(bool_nullable_filter_map)));
    // int filter
    let mut int_filter_map = indexmap! {};
    int_filter_map.insert("equals".to_owned(), Input::Type(Type::Int.to_optional()));
    int_filter_map.insert("in".to_owned(), Input::Type(Type::Int.wrap_in_array().to_optional()));
    int_filter_map.insert("notIn".to_owned(), Input::Type(Type::Int.wrap_in_array().to_optional()));
    int_filter_map.insert("lt".to_owned(), Input::Type(Type::Int.to_optional()));
    int_filter_map.insert("lte".to_owned(), Input::Type(Type::Int.to_optional()));
    int_filter_map.insert("gt".to_owned(), Input::Type(Type::Int.to_optional()));
    int_filter_map.insert("gte".to_owned(), Input::Type(Type::Int.to_optional()));
    int_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Int, Type::ShapeReference(ShapeReference::IntFilter)]).to_optional()));
    result.insert("IntFilter".to_owned(), Input::Shape(Shape::new(int_filter_map)));
    // int nullable filter
    let mut int_nullable_filter_map = indexmap! {};
    int_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::Int, Type::Null]).to_optional()));
    int_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::Int, Type::Null]).wrap_in_array().to_optional()));
    int_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::Int, Type::Null]).wrap_in_array().to_optional()));
    int_nullable_filter_map.insert("lt".to_owned(), Input::Type(Type::Int.to_optional()));
    int_nullable_filter_map.insert("lte".to_owned(), Input::Type(Type::Int.to_optional()));
    int_nullable_filter_map.insert("gt".to_owned(), Input::Type(Type::Int.to_optional()));
    int_nullable_filter_map.insert("gte".to_owned(), Input::Type(Type::Int.to_optional()));
    int_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Int, Type::Null, Type::ShapeReference(ShapeReference::IntNullableFilter)]).to_optional()));
    result.insert("IntNullableFilter".to_owned(), Input::Shape(Shape::new(int_nullable_filter_map)));
    // int64 filter
    let mut int_64_filter_map = indexmap! {};
    int_64_filter_map.insert("equals".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_filter_map.insert("in".to_owned(), Input::Type(Type::Int64.wrap_in_array().to_optional()));
    int_64_filter_map.insert("notIn".to_owned(), Input::Type(Type::Int64.wrap_in_array().to_optional()));
    int_64_filter_map.insert("lt".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_filter_map.insert("lte".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_filter_map.insert("gt".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_filter_map.insert("gte".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Int64, Type::ShapeReference(ShapeReference::Int64Filter)]).to_optional()));
    result.insert("Int64Filter".to_owned(), Input::Shape(Shape::new(int_64_filter_map)));
    // int64 nullable filter
    let mut int_64_nullable_filter_map = indexmap! {};
    int_64_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::Int64, Type::Null]).to_optional()));
    int_64_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::Int64, Type::Null]).wrap_in_array().to_optional()));
    int_64_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::Int64, Type::Null]).wrap_in_array().to_optional()));
    int_64_nullable_filter_map.insert("lt".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_nullable_filter_map.insert("lte".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_nullable_filter_map.insert("gt".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_nullable_filter_map.insert("gte".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Int64, Type::Null, Type::ShapeReference(ShapeReference::Int64NullableFilter)]).to_optional()));
    result.insert("Int64NullableFilter".to_owned(), Input::Shape(Shape::new(int_64_nullable_filter_map)));
    // float32 filter
    let mut float_32_filter_map = indexmap! {};
    float_32_filter_map.insert("equals".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_filter_map.insert("in".to_owned(), Input::Type(Type::Float32.wrap_in_array().to_optional()));
    float_32_filter_map.insert("notIn".to_owned(), Input::Type(Type::Float32.wrap_in_array().to_optional()));
    float_32_filter_map.insert("lt".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_filter_map.insert("lte".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_filter_map.insert("gt".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_filter_map.insert("gte".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Float32, Type::ShapeReference(ShapeReference::Float32Filter)]).to_optional()));
    result.insert("Float32Filter".to_owned(), Input::Shape(Shape::new(float_32_filter_map)));
    // float32 nullable filter
    let mut float_32_nullable_filter_map = indexmap! {};
    float_32_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::Float32, Type::Null]).to_optional()));
    float_32_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::Float32, Type::Null]).wrap_in_array().to_optional()));
    float_32_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::Float32, Type::Null]).wrap_in_array().to_optional()));
    float_32_nullable_filter_map.insert("lt".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_nullable_filter_map.insert("lte".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_nullable_filter_map.insert("gt".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_nullable_filter_map.insert("gte".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Float32, Type::Null, Type::ShapeReference(ShapeReference::Float32NullableFilter)]).to_optional()));
    result.insert("Float32NullableFilter".to_owned(), Input::Shape(Shape::new(float_32_nullable_filter_map)));
    // float filter
    let mut float_filter_map = indexmap! {};
    float_filter_map.insert("equals".to_owned(), Input::Type(Type::Float.to_optional()));
    float_filter_map.insert("in".to_owned(), Input::Type(Type::Float.wrap_in_array().to_optional()));
    float_filter_map.insert("notIn".to_owned(), Input::Type(Type::Float.wrap_in_array().to_optional()));
    float_filter_map.insert("lt".to_owned(), Input::Type(Type::Float.to_optional()));
    float_filter_map.insert("lte".to_owned(), Input::Type(Type::Float.to_optional()));
    float_filter_map.insert("gt".to_owned(), Input::Type(Type::Float.to_optional()));
    float_filter_map.insert("gte".to_owned(), Input::Type(Type::Float.to_optional()));
    float_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Float, Type::ShapeReference(ShapeReference::FloatFilter)]).to_optional()));
    result.insert("FloatFilter".to_owned(), Input::Shape(Shape::new(float_filter_map)));
    // float nullable filter
    let mut float_nullable_filter_map = indexmap! {};
    float_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::Float, Type::Null]).to_optional()));
    float_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::Float, Type::Null]).wrap_in_array().to_optional()));
    float_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::Float, Type::Null]).wrap_in_array().to_optional()));
    float_nullable_filter_map.insert("lt".to_owned(), Input::Type(Type::Float.to_optional()));
    float_nullable_filter_map.insert("lte".to_owned(), Input::Type(Type::Float.to_optional()));
    float_nullable_filter_map.insert("gt".to_owned(), Input::Type(Type::Float.to_optional()));
    float_nullable_filter_map.insert("gte".to_owned(), Input::Type(Type::Float.to_optional()));
    float_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Float, Type::Null, Type::ShapeReference(ShapeReference::FloatNullableFilter)]).to_optional()));
    result.insert("FloatNullableFilter".to_owned(), Input::Shape(Shape::new(float_nullable_filter_map)));
    // decimal filter
    let mut decimal_filter_map = indexmap! {};
    decimal_filter_map.insert("equals".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_filter_map.insert("in".to_owned(), Input::Type(Type::Decimal.wrap_in_array().to_optional()));
    decimal_filter_map.insert("notIn".to_owned(), Input::Type(Type::Decimal.wrap_in_array().to_optional()));
    decimal_filter_map.insert("lt".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_filter_map.insert("lte".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_filter_map.insert("gt".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_filter_map.insert("gte".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Decimal, Type::ShapeReference(ShapeReference::DecimalFilter)]).to_optional()));
    result.insert("DecimalFilter".to_owned(), Input::Shape(Shape::new(decimal_filter_map)));
    // decimal nullable filter
    let mut decimal_nullable_filter_map = indexmap! {};
    decimal_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::Decimal, Type::Null]).to_optional()));
    decimal_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::Decimal, Type::Null]).wrap_in_array().to_optional()));
    decimal_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::Decimal, Type::Null]).wrap_in_array().to_optional()));
    decimal_nullable_filter_map.insert("lt".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_nullable_filter_map.insert("lte".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_nullable_filter_map.insert("gt".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_nullable_filter_map.insert("gte".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Decimal, Type::Null, Type::ShapeReference(ShapeReference::DecimalNullableFilter)]).to_optional()));
    result.insert("DecimalNullableFilter".to_owned(), Input::Shape(Shape::new(decimal_nullable_filter_map)));
    // date filter
    let mut date_filter_map = indexmap! {};
    date_filter_map.insert("equals".to_owned(), Input::Type(Type::Date.to_optional()));
    date_filter_map.insert("in".to_owned(), Input::Type(Type::Date.wrap_in_array().to_optional()));
    date_filter_map.insert("notIn".to_owned(), Input::Type(Type::Date.wrap_in_array().to_optional()));
    date_filter_map.insert("lt".to_owned(), Input::Type(Type::Date.to_optional()));
    date_filter_map.insert("lte".to_owned(), Input::Type(Type::Date.to_optional()));
    date_filter_map.insert("gt".to_owned(), Input::Type(Type::Date.to_optional()));
    date_filter_map.insert("gte".to_owned(), Input::Type(Type::Date.to_optional()));
    date_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Date, Type::ShapeReference(ShapeReference::DateFilter)]).to_optional()));
    result.insert("DateFilter".to_owned(), Input::Shape(Shape::new(date_filter_map)));
    // date nullable filter
    let mut date_nullable_filter_map = indexmap! {};
    date_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::Date, Type::Null]).to_optional()));
    date_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::Date, Type::Null]).wrap_in_array().to_optional()));
    date_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::Date, Type::Null]).wrap_in_array().to_optional()));
    date_nullable_filter_map.insert("lt".to_owned(), Input::Type(Type::Date.to_optional()));
    date_nullable_filter_map.insert("lte".to_owned(), Input::Type(Type::Date.to_optional()));
    date_nullable_filter_map.insert("gt".to_owned(), Input::Type(Type::Date.to_optional()));
    date_nullable_filter_map.insert("gte".to_owned(), Input::Type(Type::Date.to_optional()));
    date_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Date, Type::Null, Type::ShapeReference(ShapeReference::DateNullableFilter)]).to_optional()));
    result.insert("DateNullableFilter".to_owned(), Input::Shape(Shape::new(date_nullable_filter_map)));
    // datetime filter
    let mut datetime_filter_map = indexmap! {};
    datetime_filter_map.insert("equals".to_owned(), Input::Type(Type::DateTime.to_optional()));
    datetime_filter_map.insert("in".to_owned(), Input::Type(Type::DateTime.wrap_in_array().to_optional()));
    datetime_filter_map.insert("notIn".to_owned(), Input::Type(Type::DateTime.wrap_in_array().to_optional()));
    datetime_filter_map.insert("lt".to_owned(), Input::Type(Type::DateTime.to_optional()));
    datetime_filter_map.insert("lte".to_owned(), Input::Type(Type::DateTime.to_optional()));
    datetime_filter_map.insert("gt".to_owned(), Input::Type(Type::DateTime.to_optional()));
    datetime_filter_map.insert("gte".to_owned(), Input::Type(Type::DateTime.to_optional()));
    datetime_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::DateTime, Type::ShapeReference(ShapeReference::DateTimeFilter)]).to_optional()));
    result.insert("DateTimeFilter".to_owned(), Input::Shape(Shape::new(datetime_filter_map)));
    // datetime nullable filter
    let mut datetime_nullable_filter_map = indexmap! {};
    datetime_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::DateTime, Type::Null]).to_optional()));
    datetime_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::DateTime, Type::Null]).wrap_in_array().to_optional()));
    datetime_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::DateTime, Type::Null]).wrap_in_array().to_optional()));
    datetime_nullable_filter_map.insert("lt".to_owned(), Input::Type(Type::DateTime.to_optional()));
    datetime_nullable_filter_map.insert("lte".to_owned(), Input::Type(Type::DateTime.to_optional()));
    datetime_nullable_filter_map.insert("gt".to_owned(), Input::Type(Type::DateTime.to_optional()));
    datetime_nullable_filter_map.insert("gte".to_owned(), Input::Type(Type::DateTime.to_optional()));
    datetime_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::DateTime, Type::Null, Type::ShapeReference(ShapeReference::DateTimeNullableFilter)]).to_optional()));
    result.insert("DateTimeNullableFilter".to_owned(), Input::Shape(Shape::new(datetime_nullable_filter_map)));
    // object id filter
    let mut object_id_filter_map = indexmap! {};
    object_id_filter_map.insert("equals".to_owned(), Input::Type(Type::ObjectId.to_optional()));
    object_id_filter_map.insert("in".to_owned(), Input::Type(Type::ObjectId.wrap_in_array().to_optional()));
    object_id_filter_map.insert("notIn".to_owned(), Input::Type(Type::ObjectId.wrap_in_array().to_optional()));
    object_id_filter_map.insert("lt".to_owned(), Input::Type(Type::ObjectId.to_optional()));
    object_id_filter_map.insert("lte".to_owned(), Input::Type(Type::ObjectId.to_optional()));
    object_id_filter_map.insert("gt".to_owned(), Input::Type(Type::ObjectId.to_optional()));
    object_id_filter_map.insert("gte".to_owned(), Input::Type(Type::ObjectId.to_optional()));
    object_id_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::ObjectId, Type::ShapeReference(ShapeReference::ObjectIdFilter)]).to_optional()));
    result.insert("ObjectIdFilter".to_owned(), Input::Shape(Shape::new(object_id_filter_map)));
    // object id nullable filter
    let mut object_id_nullable_filter_map = indexmap! {};
    object_id_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::ObjectId, Type::Null]).to_optional()));
    object_id_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::ObjectId, Type::Null]).wrap_in_array().to_optional()));
    object_id_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::ObjectId, Type::Null]).wrap_in_array().to_optional()));
    object_id_nullable_filter_map.insert("lt".to_owned(), Input::Type(Type::ObjectId.to_optional()));
    object_id_nullable_filter_map.insert("lte".to_owned(), Input::Type(Type::ObjectId.to_optional()));
    object_id_nullable_filter_map.insert("gt".to_owned(), Input::Type(Type::ObjectId.to_optional()));
    object_id_nullable_filter_map.insert("gte".to_owned(), Input::Type(Type::ObjectId.to_optional()));
    object_id_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::ObjectId, Type::Null, Type::ShapeReference(ShapeReference::ObjectIdNullableFilter)]).to_optional()));
    result.insert("ObjectIdNullableFilter".to_owned(), Input::Shape(Shape::new(object_id_nullable_filter_map)));
    // string filter
    let mut string_filter_map = indexmap! {};
    string_filter_map.insert("equals".to_owned(), Input::Type(Type::String.to_optional()));
    string_filter_map.insert("in".to_owned(), Input::Type(Type::String.wrap_in_array().to_optional()));
    string_filter_map.insert("notIn".to_owned(), Input::Type(Type::String.wrap_in_array().to_optional()));
    string_filter_map.insert("lt".to_owned(), Input::Type(Type::String.to_optional()));
    string_filter_map.insert("lte".to_owned(), Input::Type(Type::String.to_optional()));
    string_filter_map.insert("gt".to_owned(), Input::Type(Type::String.to_optional()));
    string_filter_map.insert("gte".to_owned(), Input::Type(Type::String.to_optional()));
    string_filter_map.insert("contains".to_owned(), Input::Type(Type::String.to_optional()));
    string_filter_map.insert("startsWith".to_owned(), Input::Type(Type::String.to_optional()));
    string_filter_map.insert("endsWith".to_owned(), Input::Type(Type::String.to_optional()));
    string_filter_map.insert("matches".to_owned(), Input::Type(Type::String.to_optional()));
    string_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::String, Type::ShapeReference(ShapeReference::StringFilter)]).to_optional()));
    result.insert("StringFilter".to_owned(), Input::Shape(Shape::new(string_filter_map)));
    // string nullable filter
    let mut string_nullable_filter_map = indexmap! {};
    string_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::String, Type::Null]).to_optional()));
    string_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::String, Type::Null]).wrap_in_array().to_optional()));
    string_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::String, Type::Null]).wrap_in_array().to_optional()));
    string_nullable_filter_map.insert("lt".to_owned(), Input::Type(Type::String.to_optional()));
    string_nullable_filter_map.insert("lte".to_owned(), Input::Type(Type::String.to_optional()));
    string_nullable_filter_map.insert("gt".to_owned(), Input::Type(Type::String.to_optional()));
    string_nullable_filter_map.insert("gte".to_owned(), Input::Type(Type::String.to_optional()));
    string_nullable_filter_map.insert("contains".to_owned(), Input::Type(Type::String.to_optional()));
    string_nullable_filter_map.insert("startsWith".to_owned(), Input::Type(Type::String.to_optional()));
    string_nullable_filter_map.insert("endsWith".to_owned(), Input::Type(Type::String.to_optional()));
    string_nullable_filter_map.insert("matches".to_owned(), Input::Type(Type::String.to_optional()));
    string_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::String, Type::Null, Type::ShapeReference(ShapeReference::StringNullableFilter)]).to_optional()));
    result.insert("StringNullableFilter".to_owned(), Input::Shape(Shape::new(string_nullable_filter_map)));
    // enum filter

    // enum nullable filter
    // array filter
    // array nullable filter
    result
});

pub(super) static STATIC_WHERE_INPUT_FOR_TYPE: Lazy<IndexMap<Type, Input>> = Lazy::new(|| {
    let mut result = indexmap! {};
    result.insert(Type::String, Input::S)
    //result.insert(Type::String.to_optional(), )
    result
});