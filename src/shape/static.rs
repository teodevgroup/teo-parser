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
    result.insert("BoolFilter".to_owned(), Input::Shape(Shape::new(bool_filter_map.clone())));
    // bool nullable filter
    let mut bool_nullable_filter_map = indexmap! {};
    bool_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::Bool, Type::Null]).to_optional()));
    bool_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::Bool, Type::Null, Type::ShapeReference(ShapeReference::BoolNullableFilter)]).to_optional()));
    result.insert("BoolNullableFilter".to_owned(), Input::Shape(Shape::new(bool_nullable_filter_map.clone())));
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
    result.insert("IntFilter".to_owned(), Input::Shape(Shape::new(int_filter_map.clone())));
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
    result.insert("IntNullableFilter".to_owned(), Input::Shape(Shape::new(int_nullable_filter_map.clone())));
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
    result.insert("Int64Filter".to_owned(), Input::Shape(Shape::new(int_64_filter_map.clone())));
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
    result.insert("Int64NullableFilter".to_owned(), Input::Shape(Shape::new(int_64_nullable_filter_map.clone())));
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
    result.insert("Float32Filter".to_owned(), Input::Shape(Shape::new(float_32_filter_map.clone())));
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
    result.insert("Float32NullableFilter".to_owned(), Input::Shape(Shape::new(float_32_nullable_filter_map.clone())));
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
    result.insert("FloatFilter".to_owned(), Input::Shape(Shape::new(float_filter_map.clone())));
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
    result.insert("FloatNullableFilter".to_owned(), Input::Shape(Shape::new(float_nullable_filter_map.clone())));
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
    result.insert("DecimalFilter".to_owned(), Input::Shape(Shape::new(decimal_filter_map.clone())));
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
    result.insert("DecimalNullableFilter".to_owned(), Input::Shape(Shape::new(decimal_nullable_filter_map.clone())));
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
    result.insert("DateFilter".to_owned(), Input::Shape(Shape::new(date_filter_map.clone())));
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
    result.insert("DateNullableFilter".to_owned(), Input::Shape(Shape::new(date_nullable_filter_map.clone())));
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
    result.insert("DateTimeFilter".to_owned(), Input::Shape(Shape::new(datetime_filter_map.clone())));
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
    result.insert("DateTimeNullableFilter".to_owned(), Input::Shape(Shape::new(datetime_nullable_filter_map.clone())));
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
    result.insert("ObjectIdFilter".to_owned(), Input::Shape(Shape::new(object_id_filter_map.clone())));
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
    result.insert("ObjectIdNullableFilter".to_owned(), Input::Shape(Shape::new(object_id_nullable_filter_map.clone())));
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
    result.insert("StringFilter".to_owned(), Input::Shape(Shape::new(string_filter_map.clone())));
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
    result.insert("StringNullableFilter".to_owned(), Input::Shape(Shape::new(string_nullable_filter_map.clone())));
    // enum filter
    let mut enum_filter_map = indexmap! {};
    enum_filter_map.insert("equals".to_owned(), Input::Type(Type::GenericItem("T".to_string()).to_optional()));
    enum_filter_map.insert("in".to_owned(), Input::Type(Type::GenericItem("T".to_string()).wrap_in_array().to_optional()));
    enum_filter_map.insert("notIn".to_owned(), Input::Type(Type::GenericItem("T".to_string()).wrap_in_array().to_optional()));
    enum_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::GenericItem("T".to_string()), Type::ShapeReference(ShapeReference::EnumFilter(Box::new(Type::GenericItem("T".to_string()))))]).to_optional()));
    result.insert("EnumFilter".to_owned(), Input::Shape(Shape::new(enum_filter_map.clone())));
    // enum nullable filter
    let mut enum_nullable_filter_map = indexmap! {};
    enum_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::GenericItem("T".to_string()), Type::Null]).to_optional()));
    enum_nullable_filter_map.insert("in".to_owned(), Input::Type(Type::Union(vec![Type::GenericItem("T".to_string()), Type::Null]).wrap_in_array().to_optional()));
    enum_nullable_filter_map.insert("notIn".to_owned(), Input::Type(Type::Union(vec![Type::GenericItem("T".to_string()), Type::Null]).wrap_in_array().to_optional()));
    enum_nullable_filter_map.insert("not".to_owned(), Input::Type(Type::Union(vec![Type::GenericItem("T".to_string()), Type::Null, Type::ShapeReference(ShapeReference::EnumNullableFilter(Box::new(Type::GenericItem("T".to_string()))))]).to_optional()));
    result.insert("EnumNullableFilter".to_owned(), Input::Shape(Shape::new(enum_nullable_filter_map.clone())));
    // array filter
    let mut array_filter_map = indexmap! {};
    array_filter_map.insert("equals".to_owned(), Input::Type(Type::GenericItem("T".to_string()).wrap_in_array().to_optional()));
    array_filter_map.insert("has".to_owned(), Input::Type(Type::GenericItem("T".to_string()).to_optional()));
    array_filter_map.insert("hasSome".to_owned(), Input::Type(Type::GenericItem("T".to_string()).wrap_in_array().to_optional()));
    array_filter_map.insert("hasEvery".to_owned(), Input::Type(Type::GenericItem("T".to_string()).wrap_in_array().to_optional()));
    array_filter_map.insert("isEmpty".to_owned(), Input::Type(Type::Bool.to_optional()));
    array_filter_map.insert("length".to_owned(), Input::Type(Type::Int.to_optional()));
    result.insert("ArrayFilter".to_owned(), Input::Shape(Shape::new(array_filter_map.clone())));
    // array nullable filter
    let mut array_nullable_filter_map = indexmap! {};
    array_nullable_filter_map.insert("equals".to_owned(), Input::Type(Type::Union(vec![Type::GenericItem("T".to_string()).wrap_in_array(), Type::Null]).to_optional()));
    array_nullable_filter_map.insert("has".to_owned(), Input::Type(Type::GenericItem("T".to_string()).to_optional()));
    array_nullable_filter_map.insert("hasSome".to_owned(), Input::Type(Type::GenericItem("T".to_string()).wrap_in_array().to_optional()));
    array_nullable_filter_map.insert("hasEvery".to_owned(), Input::Type(Type::GenericItem("T".to_string()).wrap_in_array().to_optional()));
    array_nullable_filter_map.insert("isEmpty".to_owned(), Input::Type(Type::Bool.to_optional()));
    array_nullable_filter_map.insert("length".to_owned(), Input::Type(Type::Int.to_optional()));
    result.insert("ArrayFilter".to_owned(), Input::Shape(Shape::new(array_nullable_filter_map.clone())));

    // bool with aggregates filter
    bool_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    bool_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::BoolFilter).to_optional()));
    bool_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::BoolFilter).to_optional()));
    result.insert("BoolWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(bool_filter_map)));
    // bool nullable with aggregates filter
    bool_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    bool_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::BoolNullableFilter).to_optional()));
    bool_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::BoolNullableFilter).to_optional()));
    result.insert("BoolWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(bool_nullable_filter_map)));
    // int with aggregates filter
    int_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    int_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::IntFilter).to_optional()));
    int_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::IntFilter).to_optional()));
    int_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatFilter).to_optional()));
    int_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    result.insert("IntWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(int_filter_map)));
    // int nullable with aggregates filter
    int_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    int_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::IntNullableFilter).to_optional()));
    int_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::IntNullableFilter).to_optional()));
    int_nullable_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatNullableFilter).to_optional()));
    int_nullable_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64NullableFilter).to_optional()));
    result.insert("IntNullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(int_nullable_filter_map)));
    // int 64 with aggregates filter
    int_64_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    int_64_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    int_64_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    int_64_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatFilter).to_optional()));
    int_64_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    result.insert("Int64WithAggregatesFilter".to_owned(), Input::Shape(Shape::new(int_64_filter_map)));
    // int 64 nullable with aggregates filter
    int_64_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    int_64_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64NullableFilter).to_optional()));
    int_64_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64NullableFilter).to_optional()));
    int_64_nullable_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatNullableFilter).to_optional()));
    int_64_nullable_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64NullableFilter).to_optional()));
    result.insert("Int64NullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(int_64_nullable_filter_map)));
    // float 32 with aggregates filter
    float_32_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    float_32_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Float32Filter).to_optional()));
    float_32_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Float32Filter).to_optional()));
    float_32_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Float32Filter).to_optional()));
    float_32_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatFilter).to_optional()));
    result.insert("Float32WithAggregatesFilter".to_owned(), Input::Shape(Shape::new(float_32_filter_map)));
    // float 32 nullable with aggregates filter
    float_32_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    float_32_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Float32NullableFilter).to_optional()));
    float_32_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Float32NullableFilter).to_optional()));
    float_32_nullable_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Float32NullableFilter).to_optional()));
    float_32_nullable_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatNullableFilter).to_optional()));
    result.insert("Float32NullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(float_32_nullable_filter_map)));
    // float with aggregates filter
    float_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    float_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatFilter).to_optional()));
    float_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatFilter).to_optional()));
    float_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatFilter).to_optional()));
    float_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatFilter).to_optional()));
    result.insert("FloatWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(float_filter_map)));
    // float nullable with aggregates filter
    float_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    float_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatNullableFilter).to_optional()));
    float_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatNullableFilter).to_optional()));
    float_nullable_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatNullableFilter).to_optional()));
    float_nullable_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::FloatNullableFilter).to_optional()));
    result.insert("FloatNullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(float_nullable_filter_map)));
    // decimal with aggregates filter
    decimal_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    decimal_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DecimalFilter).to_optional()));
    decimal_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DecimalFilter).to_optional()));
    decimal_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DecimalFilter).to_optional()));
    decimal_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DecimalFilter).to_optional()));
    result.insert("DecimalWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(decimal_filter_map)));
    // decimal nullable with aggregates filter
    decimal_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    decimal_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DecimalNullableFilter).to_optional()));
    decimal_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DecimalNullableFilter).to_optional()));
    decimal_nullable_filter_map.insert("_avg".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DecimalNullableFilter).to_optional()));
    decimal_nullable_filter_map.insert("_sum".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DecimalNullableFilter).to_optional()));
    result.insert("DecimalNullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(decimal_nullable_filter_map)));
    // date with aggregates filter
    date_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    date_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DateFilter).to_optional()));
    date_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DateFilter).to_optional()));
    result.insert("DateWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(date_filter_map)));
    // date nullable with aggregates filter
    date_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    date_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DateNullableFilter).to_optional()));
    date_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DateNullableFilter).to_optional()));
    result.insert("DateNullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(date_nullable_filter_map)));
    // date time with aggregates filter
    datetime_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    datetime_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DateTimeFilter).to_optional()));
    datetime_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DateTimeFilter).to_optional()));
    result.insert("DateTimeWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(datetime_filter_map)));
    // date time nullable with aggregates filter
    datetime_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    datetime_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DateTimeNullableFilter).to_optional()));
    datetime_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::DateTimeNullableFilter).to_optional()));
    result.insert("DateTimeNullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(datetime_nullable_filter_map)));
    // object id with aggregates filter
    object_id_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    object_id_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ObjectIdFilter).to_optional()));
    object_id_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ObjectIdFilter).to_optional()));
    result.insert("ObjectIdWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(object_id_filter_map)));
    // object id nullable with aggregates filter
    object_id_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    object_id_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ObjectIdNullableFilter).to_optional()));
    object_id_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ObjectIdNullableFilter).to_optional()));
    result.insert("ObjectIdNullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(object_id_nullable_filter_map)));
    // string with aggregates filter
    string_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    string_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::StringFilter).to_optional()));
    string_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::StringFilter).to_optional()));
    result.insert("StringWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(string_filter_map)));
    // string nullable with aggregates filter
    string_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    string_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::StringNullableFilter).to_optional()));
    string_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::StringNullableFilter).to_optional()));
    result.insert("StringNullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(string_nullable_filter_map)));
    // enum with aggregates filter
    enum_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    enum_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::EnumFilter(Box::new(Type::GenericItem("T".to_owned())))).to_optional()));
    enum_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::EnumFilter(Box::new(Type::GenericItem("T".to_owned())))).to_optional()));
    result.insert("EnumWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(enum_filter_map)));
    // enum nullable with aggregates filter
    enum_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    enum_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::EnumNullableFilter(Box::new(Type::GenericItem("T".to_owned())))).to_optional()));
    enum_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::EnumNullableFilter(Box::new(Type::GenericItem("T".to_owned())))).to_optional()));
    result.insert("EnumNullableWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(enum_nullable_filter_map)));
    // array with aggregates filter
    array_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    array_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ArrayFilter(Box::new(Type::GenericItem("T".to_owned())))).to_optional()));
    array_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ArrayFilter(Box::new(Type::GenericItem("T".to_owned())))).to_optional()));
    result.insert("ArrayWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(array_filter_map)));
    // array nullable with aggregates filter
    array_nullable_filter_map.insert("_count".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::Int64Filter).to_optional()));
    array_nullable_filter_map.insert("_min".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ArrayNullableFilter(Box::new(Type::GenericItem("T".to_owned())))).to_optional()));
    array_nullable_filter_map.insert("_max".to_owned(), Input::Type(Type::ShapeReference(ShapeReference::ArrayNullableFilter(Box::new(Type::GenericItem("T".to_owned())))).to_optional()));
    result.insert("ArrayWithAggregatesFilter".to_owned(), Input::Shape(Shape::new(array_nullable_filter_map)));

    // int atomic update operation input
    let mut int_atomic_update_operation_input_map = indexmap! {};
    int_atomic_update_operation_input_map.insert("increment".to_owned(), Input::Type(Type::Int.to_optional()));
    int_atomic_update_operation_input_map.insert("decrement".to_owned(), Input::Type(Type::Int.to_optional()));
    int_atomic_update_operation_input_map.insert("multiply".to_owned(), Input::Type(Type::Int.to_optional()));
    int_atomic_update_operation_input_map.insert("divide".to_owned(), Input::Type(Type::Int.to_optional()));
    result.insert("IntAtomicUpdateOperationInput".to_owned(), Input::Shape(Shape::new(int_atomic_update_operation_input_map)));
    // int64 atomic update operation input
    let mut int_64_atomic_update_operation_input_map = indexmap! {};
    int_64_atomic_update_operation_input_map.insert("increment".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_atomic_update_operation_input_map.insert("decrement".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_atomic_update_operation_input_map.insert("multiply".to_owned(), Input::Type(Type::Int64.to_optional()));
    int_64_atomic_update_operation_input_map.insert("divide".to_owned(), Input::Type(Type::Int64.to_optional()));
    result.insert("Int64AtomicUpdateOperationInput".to_owned(), Input::Shape(Shape::new(int_64_atomic_update_operation_input_map)));
    // float32 atomic update operation input
    let mut float_32_atomic_update_operation_input_map = indexmap! {};
    float_32_atomic_update_operation_input_map.insert("increment".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_atomic_update_operation_input_map.insert("decrement".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_atomic_update_operation_input_map.insert("multiply".to_owned(), Input::Type(Type::Float32.to_optional()));
    float_32_atomic_update_operation_input_map.insert("divide".to_owned(), Input::Type(Type::Float32.to_optional()));
    result.insert("Float32AtomicUpdateOperationInput".to_owned(), Input::Shape(Shape::new(float_32_atomic_update_operation_input_map)));
    // float atomic update operation input
    let mut float_atomic_update_operation_input_map = indexmap! {};
    float_atomic_update_operation_input_map.insert("increment".to_owned(), Input::Type(Type::Float.to_optional()));
    float_atomic_update_operation_input_map.insert("decrement".to_owned(), Input::Type(Type::Float.to_optional()));
    float_atomic_update_operation_input_map.insert("multiply".to_owned(), Input::Type(Type::Float.to_optional()));
    float_atomic_update_operation_input_map.insert("divide".to_owned(), Input::Type(Type::Float.to_optional()));
    result.insert("FloatAtomicUpdateOperationInput".to_owned(), Input::Shape(Shape::new(float_atomic_update_operation_input_map)));
    // decimal atomic update operation input
    let mut decimal_atomic_update_operation_input_map = indexmap! {};
    decimal_atomic_update_operation_input_map.insert("increment".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_atomic_update_operation_input_map.insert("decrement".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_atomic_update_operation_input_map.insert("multiply".to_owned(), Input::Type(Type::Decimal.to_optional()));
    decimal_atomic_update_operation_input_map.insert("divide".to_owned(), Input::Type(Type::Decimal.to_optional()));
    result.insert("DecimalAtomicUpdateOperationInput".to_owned(), Input::Shape(Shape::new(decimal_atomic_update_operation_input_map)));
    // array atomic update operation input
    let mut array_atomic_update_operation_input_map = indexmap! {};
    array_atomic_update_operation_input_map.insert("push".to_owned(), Input::Type(Type::GenericItem("T".to_owned()).to_optional()));
    result.insert("ArrayAtomicUpdateOperationInput".to_owned(), Input::Shape(Shape::new(array_atomic_update_operation_input_map)));

    result
});

pub static STATIC_WHERE_INPUT_FOR_TYPE: Lazy<IndexMap<Type, Input>> = Lazy::new(|| {
    let mut result = indexmap! {};
    result.insert(Type::Bool, Input::Type(Type::Union(vec![Type::Bool, Type::ShapeReference(ShapeReference::BoolFilter)]).to_optional()));
    result.insert(Type::Bool.to_optional(), Input::Type(Type::Union(vec![Type::Bool, Type::Null, Type::ShapeReference(ShapeReference::BoolNullableFilter)]).to_optional()));
    result.insert(Type::Int, Input::Type(Type::Union(vec![Type::Int, Type::ShapeReference(ShapeReference::IntFilter)]).to_optional()));
    result.insert(Type::Int.to_optional(), Input::Type(Type::Union(vec![Type::Int, Type::Null, Type::ShapeReference(ShapeReference::IntNullableFilter)]).to_optional()));
    result.insert(Type::Int64, Input::Type(Type::Union(vec![Type::Int64, Type::ShapeReference(ShapeReference::Int64Filter)]).to_optional()));
    result.insert(Type::Int64.to_optional(), Input::Type(Type::Union(vec![Type::Int64, Type::Null, Type::ShapeReference(ShapeReference::Int64NullableFilter)]).to_optional()));
    result.insert(Type::Float32, Input::Type(Type::Union(vec![Type::Float32, Type::ShapeReference(ShapeReference::Float32Filter)]).to_optional()));
    result.insert(Type::Float32.to_optional(), Input::Type(Type::Union(vec![Type::Float32, Type::Null, Type::ShapeReference(ShapeReference::Float32NullableFilter)]).to_optional()));
    result.insert(Type::Float, Input::Type(Type::Union(vec![Type::Float, Type::ShapeReference(ShapeReference::FloatFilter)]).to_optional()));
    result.insert(Type::Float.to_optional(), Input::Type(Type::Union(vec![Type::Float, Type::Null, Type::ShapeReference(ShapeReference::FloatNullableFilter)]).to_optional()));
    result.insert(Type::Decimal, Input::Type(Type::Union(vec![Type::Decimal, Type::ShapeReference(ShapeReference::DecimalFilter)]).to_optional()));
    result.insert(Type::Decimal.to_optional(), Input::Type(Type::Union(vec![Type::Decimal, Type::Null, Type::ShapeReference(ShapeReference::DecimalNullableFilter)]).to_optional()));
    result.insert(Type::Date, Input::Type(Type::Union(vec![Type::Date, Type::ShapeReference(ShapeReference::DateFilter)]).to_optional()));
    result.insert(Type::Date.to_optional(), Input::Type(Type::Union(vec![Type::Date, Type::Null, Type::ShapeReference(ShapeReference::DateNullableFilter)]).to_optional()));
    result.insert(Type::DateTime, Input::Type(Type::Union(vec![Type::DateTime, Type::ShapeReference(ShapeReference::DateTimeFilter)]).to_optional()));
    result.insert(Type::DateTime.to_optional(), Input::Type(Type::Union(vec![Type::DateTime, Type::Null, Type::ShapeReference(ShapeReference::DateTimeNullableFilter)]).to_optional()));
    result.insert(Type::ObjectId, Input::Type(Type::Union(vec![Type::ObjectId, Type::ShapeReference(ShapeReference::ObjectIdFilter)]).to_optional()));
    result.insert(Type::ObjectId.to_optional(), Input::Type(Type::Union(vec![Type::ObjectId, Type::Null, Type::ShapeReference(ShapeReference::ObjectIdNullableFilter)]).to_optional()));
    result.insert(Type::String, Input::Type(Type::Union(vec![Type::String, Type::ShapeReference(ShapeReference::StringFilter)]).to_optional()));
    result.insert(Type::String.to_optional(), Input::Type(Type::Union(vec![Type::String, Type::Null, Type::ShapeReference(ShapeReference::StringNullableFilter)]).to_optional()));
    result
});

pub static STATIC_WHERE_WITH_AGGREGATES_INPUT_FOR_TYPE: Lazy<IndexMap<Type, Input>> = Lazy::new(|| {
    let mut result = indexmap! {};
    result.insert(Type::Bool, Input::Type(Type::Union(vec![Type::Bool, Type::ShapeReference(ShapeReference::BoolWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Bool.to_optional(), Input::Type(Type::Union(vec![Type::Bool, Type::Null, Type::ShapeReference(ShapeReference::BoolNullableWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Int, Input::Type(Type::Union(vec![Type::Int, Type::ShapeReference(ShapeReference::IntWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Int.to_optional(), Input::Type(Type::Union(vec![Type::Int, Type::Null, Type::ShapeReference(ShapeReference::IntNullableWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Int64, Input::Type(Type::Union(vec![Type::Int64, Type::ShapeReference(ShapeReference::Int64WithAggregatesFilter)]).to_optional()));
    result.insert(Type::Int64.to_optional(), Input::Type(Type::Union(vec![Type::Int64, Type::Null, Type::ShapeReference(ShapeReference::Int64NullableWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Float32, Input::Type(Type::Union(vec![Type::Float32, Type::ShapeReference(ShapeReference::Float32WithAggregatesFilter)]).to_optional()));
    result.insert(Type::Float32.to_optional(), Input::Type(Type::Union(vec![Type::Float32, Type::Null, Type::ShapeReference(ShapeReference::Float32NullableWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Float, Input::Type(Type::Union(vec![Type::Float, Type::ShapeReference(ShapeReference::FloatWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Float.to_optional(), Input::Type(Type::Union(vec![Type::Float, Type::Null, Type::ShapeReference(ShapeReference::FloatNullableWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Decimal, Input::Type(Type::Union(vec![Type::Decimal, Type::ShapeReference(ShapeReference::DecimalWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Decimal.to_optional(), Input::Type(Type::Union(vec![Type::Decimal, Type::Null, Type::ShapeReference(ShapeReference::DecimalNullableWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Date, Input::Type(Type::Union(vec![Type::Date, Type::ShapeReference(ShapeReference::DateWithAggregatesFilter)]).to_optional()));
    result.insert(Type::Date.to_optional(), Input::Type(Type::Union(vec![Type::Date, Type::Null, Type::ShapeReference(ShapeReference::DateNullableWithAggregatesFilter)]).to_optional()));
    result.insert(Type::DateTime, Input::Type(Type::Union(vec![Type::DateTime, Type::ShapeReference(ShapeReference::DateTimeWithAggregatesFilter)]).to_optional()));
    result.insert(Type::DateTime.to_optional(), Input::Type(Type::Union(vec![Type::DateTime, Type::Null, Type::ShapeReference(ShapeReference::DateTimeNullableWithAggregatesFilter)]).to_optional()));
    result.insert(Type::ObjectId, Input::Type(Type::Union(vec![Type::ObjectId, Type::ShapeReference(ShapeReference::ObjectIdWithAggregatesFilter)]).to_optional()));
    result.insert(Type::ObjectId.to_optional(), Input::Type(Type::Union(vec![Type::ObjectId, Type::Null, Type::ShapeReference(ShapeReference::ObjectIdNullableWithAggregatesFilter)]).to_optional()));
    result.insert(Type::String, Input::Type(Type::Union(vec![Type::String, Type::ShapeReference(ShapeReference::StringWithAggregatesFilter)]).to_optional()));
    result.insert(Type::String.to_optional(), Input::Type(Type::Union(vec![Type::String, Type::Null, Type::ShapeReference(ShapeReference::StringNullableWithAggregatesFilter)]).to_optional()));
    result
});