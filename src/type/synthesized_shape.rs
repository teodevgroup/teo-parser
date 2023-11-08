use std::fmt::{Display, Formatter};
use educe::Educe;
use serde::Serialize;
use crate::r#type::Type;

#[derive(Debug, Clone, Eq, Serialize)]
#[derive(Educe)]
#[educe(Hash, PartialEq)]
pub enum SynthesizedShapeReference {
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
    EnumFilter(Box<Type>),
    EnumNullableFilter(Box<Type>),
    ArrayFilter(Box<Type>),
    ArrayNullableFilter(Box<Type>),
    BoolWithAggregatesFilter,
    BoolNullableWithAggregatesFilter,
    IntWithAggregatesFilter,
    IntNullableWithAggregatesFilter,
    Int64WithAggregatesFilter,
    Int64NullableWithAggregatesFilter,
    Float32WithAggregatesFilter,
    Float32NullableWithAggregatesFilter,
    FloatWithAggregatesFilter,
    FloatNullableWithAggregatesFilter,
    DecimalWithAggregatesFilter,
    DecimalNullableWithAggregatesFilter,
    DateWithAggregatesFilter,
    DateNullableWithAggregatesFilter,
    DateTimeWithAggregatesFilter,
    DateTimeNullableWithAggregatesFilter,
    ObjectIdWithAggregatesFilter,
    ObjectIdNullableWithAggregatesFilter,
    StringWithAggregatesFilter,
    StringNullableWithAggregatesFilter,
    EnumWithAggregatesFilter(Box<Type>),
    EnumNullableWithAggregatesFilter(Box<Type>),
    ArrayWithAggregatesFilter(Box<Type>),
    ArrayNullableWithAggregatesFilter(Box<Type>),
    IntAtomicUpdateOperationInput,
    Int64AtomicUpdateOperationInput,
    Float32AtomicUpdateOperationInput,
    FloatAtomicUpdateOperationInput,
    DecimalAtomicUpdateOperationInput,
    ArrayAtomicUpdateOperationInput(Box<Type>),
    Args(Vec<usize>, Vec<String>),
    FindManyArgs(Vec<usize>, Vec<String>),
    FindFirstArgs(Vec<usize>, Vec<String>),
    FindUniqueArgs(Vec<usize>, Vec<String>),
    CreateArgs(Vec<usize>, Vec<String>),
    UpdateArgs(Vec<usize>, Vec<String>),
    UpsertArgs(Vec<usize>, Vec<String>),
    CopyArgs(Vec<usize>, Vec<String>),
    DeleteArgs(Vec<usize>, Vec<String>),
    CreateManyArgs(Vec<usize>, Vec<String>),
    UpdateManyArgs(Vec<usize>, Vec<String>),
    CopyManyArgs(Vec<usize>, Vec<String>),
    DeleteManyArgs(Vec<usize>, Vec<String>),
    CountArgs(Vec<usize>, Vec<String>),
    AggregateArgs(Vec<usize>, Vec<String>),
    GroupByArgs(Vec<usize>, Vec<String>),
    RelationFilter(Vec<usize>, Vec<String>),
    ListRelationFilter(Vec<usize>, Vec<String>),
    WhereInput(Vec<usize>, Vec<String>),
    WhereUniqueInput(Vec<usize>, Vec<String>),
    ScalarFieldEnum(Vec<usize>, Vec<String>),
    ScalarWhereWithAggregatesInput(Vec<usize>, Vec<String>),
    CountAggregateInputType(Vec<usize>, Vec<String>),
    SumAggregateInputType(Vec<usize>, Vec<String>),
    AvgAggregateInputType(Vec<usize>, Vec<String>),
    MaxAggregateInputType(Vec<usize>, Vec<String>),
    MinAggregateInputType(Vec<usize>, Vec<String>),
    CreateInput(Vec<usize>, Vec<String>),
    CreateInputWithout(Vec<usize>, Vec<String>, String),
    CreateNestedOneInput(Vec<usize>, Vec<String>),
    CreateNestedOneInputWithout(Vec<usize>, Vec<String>, String),
    CreateNestedManyInput(Vec<usize>, Vec<String>),
    CreateNestedManyInputWithout(Vec<usize>, Vec<String>, String),
    UpdateInput(Vec<usize>, Vec<String>),
    UpdateInputWithout(Vec<usize>, Vec<String>, String),
    UpdateNestedOneInput(Vec<usize>, Vec<String>),
    UpdateNestedOneInputWithout(Vec<usize>, Vec<String>, String),
    UpdateNestedManyInput(Vec<usize>, Vec<String>),
    UpdateNestedManyInputWithout(Vec<usize>, Vec<String>, String),
    ConnectOrCreateInput(Vec<usize>, Vec<String>),
    ConnectOrCreateInputWithout(Vec<usize>, Vec<String>, String),
    UpdateWithWhereUniqueInput(Vec<usize>, Vec<String>),
    UpdateWithWhereUniqueInputWithout(Vec<usize>, Vec<String>, String),
    UpsertWithWhereUniqueInput(Vec<usize>, Vec<String>),
    UpsertWithWhereUniqueInputWithout(Vec<usize>, Vec<String>, String),
    UpdateManyWithWhereInput(Vec<usize>, Vec<String>),
    UpdateManyWithWhereInputWithout(Vec<usize>, Vec<String>, String),
    Select(Vec<usize>, Vec<String>),
    Include(Vec<usize>, Vec<String>),
    OrderByInput(Vec<usize>, Vec<String>),
    Result(Vec<usize>, Vec<String>),
    CountAggregateResult(Vec<usize>, Vec<String>),
    SumAggregateResult(Vec<usize>, Vec<String>),
    AvgAggregateResult(Vec<usize>, Vec<String>),
    MinAggregateResult(Vec<usize>, Vec<String>),
    MaxAggregateResult(Vec<usize>, Vec<String>),
    AggregateResult(Vec<usize>, Vec<String>),
    GroupByResult(Vec<usize>, Vec<String>),
}

impl Display for SynthesizedShapeReference {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SynthesizedShapeReference::BoolFilter => f.write_str("BoolFilter"),
            SynthesizedShapeReference::BoolNullableFilter => f.write_str("BoolNullableFilter"),
            SynthesizedShapeReference::IntFilter => f.write_str("IntFilter"),
            SynthesizedShapeReference::IntNullableFilter => f.write_str("IntNullableFilter"),
            SynthesizedShapeReference::Int64Filter => f.write_str("Int64Filter"),
            SynthesizedShapeReference::Int64NullableFilter => f.write_str("Int64NullableFilter"),
            SynthesizedShapeReference::Float32Filter => f.write_str("Float32Filter"),
            SynthesizedShapeReference::Float32NullableFilter => f.write_str("Float32NullableFilter"),
            SynthesizedShapeReference::FloatFilter => f.write_str("FloatFilter"),
            SynthesizedShapeReference::FloatNullableFilter => f.write_str("FloatNullableFilter"),
            SynthesizedShapeReference::DecimalFilter => f.write_str("DecimalFilter"),
            SynthesizedShapeReference::DecimalNullableFilter => f.write_str("DecimalNullableFilter"),
            SynthesizedShapeReference::DateFilter => f.write_str("DateFilter"),
            SynthesizedShapeReference::DateNullableFilter => f.write_str("DateNullableFilter"),
            SynthesizedShapeReference::DateTimeFilter => f.write_str("DateTimeFilter"),
            SynthesizedShapeReference::DateTimeNullableFilter => f.write_str("DateTimeNullableFilter"),
            SynthesizedShapeReference::ObjectIdFilter => f.write_str("ObjectIdFilter"),
            SynthesizedShapeReference::ObjectIdNullableFilter => f.write_str("ObjectIdNullableFilter"),
            SynthesizedShapeReference::StringFilter => f.write_str("StringFilter"),
            SynthesizedShapeReference::StringNullableFilter => f.write_str("StringNullableFilter"),
            SynthesizedShapeReference::EnumFilter(t) => f.write_str(&format!("EnumFilter<{}>", t.as_ref())),
            SynthesizedShapeReference::EnumNullableFilter(t) => f.write_str(&format!("EnumNullableFilter<{}>", t.as_ref())),
            SynthesizedShapeReference::ArrayFilter(t) => f.write_str(&format!("ArrayFilter<{}>", t.as_ref())),
            SynthesizedShapeReference::ArrayNullableFilter(t) => f.write_str(&format!("ArrayNullableFilter<{}>", t.as_ref())),
            SynthesizedShapeReference::BoolWithAggregatesFilter => f.write_str("BoolWithAggregatesFilter"),
            SynthesizedShapeReference::BoolNullableWithAggregatesFilter => f.write_str("BoolNullableWithAggregatesFilter"),
            SynthesizedShapeReference::IntWithAggregatesFilter => f.write_str("IntWithAggregatesFilter"),
            SynthesizedShapeReference::IntNullableWithAggregatesFilter => f.write_str("IntNullableWithAggregatesFilter"),
            SynthesizedShapeReference::Int64WithAggregatesFilter => f.write_str("Int64WithAggregatesFilter"),
            SynthesizedShapeReference::Int64NullableWithAggregatesFilter => f.write_str("Int64NullableWithAggregatesFilter"),
            SynthesizedShapeReference::Float32WithAggregatesFilter => f.write_str("Float32WithAggregatesFilter"),
            SynthesizedShapeReference::Float32NullableWithAggregatesFilter => f.write_str("Float32NullableWithAggregatesFilter"),
            SynthesizedShapeReference::FloatWithAggregatesFilter => f.write_str("FloatWithAggregatesFilter"),
            SynthesizedShapeReference::FloatNullableWithAggregatesFilter => f.write_str("FloatNullableWithAggregatesFilter"),
            SynthesizedShapeReference::DecimalWithAggregatesFilter => f.write_str("DecimalWithAggregatesFilter"),
            SynthesizedShapeReference::DecimalNullableWithAggregatesFilter => f.write_str("DecimalNullableWithAggregatesFilter"),
            SynthesizedShapeReference::DateWithAggregatesFilter => f.write_str("DateWithAggregatesFilter"),
            SynthesizedShapeReference::DateNullableWithAggregatesFilter => f.write_str("DateNullableWithAggregatesFilter"),
            SynthesizedShapeReference::DateTimeWithAggregatesFilter => f.write_str("DateTimeWithAggregatesFilter"),
            SynthesizedShapeReference::DateTimeNullableWithAggregatesFilter => f.write_str("DateTimeNullableWithAggregatesFilter"),
            SynthesizedShapeReference::ObjectIdWithAggregatesFilter => f.write_str("ObjectIdWithAggregatesFilter"),
            SynthesizedShapeReference::ObjectIdNullableWithAggregatesFilter => f.write_str("ObjectIdNullableWithAggregatesFilter"),
            SynthesizedShapeReference::StringWithAggregatesFilter => f.write_str("StringWithAggregatesFilter"),
            SynthesizedShapeReference::StringNullableWithAggregatesFilter => f.write_str("StringNullableWithAggregatesFilter"),
            SynthesizedShapeReference::EnumWithAggregatesFilter(t) => f.write_str(&format!("EnumWithAggregatesFilter<{}>", t.as_ref())),
            SynthesizedShapeReference::EnumNullableWithAggregatesFilter(t) => f.write_str(&format!("EnumNullableWithAggregatesFilter<{}>", t.as_ref())),
            SynthesizedShapeReference::ArrayWithAggregatesFilter(t) => f.write_str(&format!("ArrayWithAggregatesFilter<{}>", t.as_ref())),
            SynthesizedShapeReference::ArrayNullableWithAggregatesFilter(t) => f.write_str(&format!("ArrayNullableWithAggregatesFilter<{}>", t.as_ref())),
            SynthesizedShapeReference::IntAtomicUpdateOperationInput => f.write_str("IntAtomicUpdateOperationInput"),
            SynthesizedShapeReference::Int64AtomicUpdateOperationInput => f.write_str("Int64AtomicUpdateOperationInput"),
            SynthesizedShapeReference::Float32AtomicUpdateOperationInput => f.write_str("Float32AtomicUpdateOperationInput"),
            SynthesizedShapeReference::FloatAtomicUpdateOperationInput => f.write_str("FloatAtomicUpdateOperationInput"),
            SynthesizedShapeReference::DecimalAtomicUpdateOperationInput => f.write_str("DecimalAtomicUpdateOperationInput"),
            SynthesizedShapeReference::ArrayAtomicUpdateOperationInput(t) => f.write_str(&format!("ArrayAtomicUpdateOperationInput{}", t.as_ref())),
            SynthesizedShapeReference::Args(_, k) => f.write_str(&format!("Args<{}>", k.join("."))),
            SynthesizedShapeReference::FindManyArgs(_, k) => f.write_str(&format!("FindManyArgs<{}>", k.join("."))),
            SynthesizedShapeReference::FindFirstArgs(_, k) => f.write_str(&format!("FindFirstArgs<{}>", k.join("."))),
            SynthesizedShapeReference::FindUniqueArgs(_, k) => f.write_str(&format!("FindUniqueArgs<{}>", k.join("."))),
            SynthesizedShapeReference::CreateArgs(_, k) => f.write_str(&format!("CreateArgs<{}>", k.join("."))),
            SynthesizedShapeReference::UpdateArgs(_, k) => f.write_str(&format!("UpdateArgs<{}>", k.join("."))),
            SynthesizedShapeReference::UpsertArgs(_, k) => f.write_str(&format!("UpsertArgs<{}>", k.join("."))),
            SynthesizedShapeReference::CopyArgs(_, k) => f.write_str(&format!("CopyArgs<{}>", k.join("."))),
            SynthesizedShapeReference::DeleteArgs(_, k) => f.write_str(&format!("DeleteArgs<{}>", k.join("."))),
            SynthesizedShapeReference::CreateManyArgs(_, k) => f.write_str(&format!("CreateManyArgs<{}>", k.join("."))),
            SynthesizedShapeReference::UpdateManyArgs(_, k) => f.write_str(&format!("UpdateManyArgs<{}>", k.join("."))),
            SynthesizedShapeReference::CopyManyArgs(_, k) => f.write_str(&format!("CopyManyArgs<{}>", k.join("."))),
            SynthesizedShapeReference::DeleteManyArgs(_, k) => f.write_str(&format!("DeleteManyArgs<{}>", k.join("."))),
            SynthesizedShapeReference::CountArgs(_, k) => f.write_str(&format!("CountArgs<{}>", k.join("."))),
            SynthesizedShapeReference::AggregateArgs(_, k) => f.write_str(&format!("AggregateArgs<{}>", k.join("."))),
            SynthesizedShapeReference::GroupByArgs(_, k) => f.write_str(&format!("GroupByArgs<{}>", k.join("."))),
            SynthesizedShapeReference::RelationFilter(_, k) => f.write_str(&format!("RelationFilter<{}>", k.join("."))),
            SynthesizedShapeReference::ListRelationFilter(_, k) => f.write_str(&format!("ListRelationFilter<{}>", k.join("."))),
            SynthesizedShapeReference::WhereInput(_, k) => f.write_str(&format!("WhereInput<{}>", k.join("."))),
            SynthesizedShapeReference::WhereUniqueInput(_, k) => f.write_str(&format!("WhereUniqueInput<{}>", k.join("."))),
            SynthesizedShapeReference::ScalarFieldEnum(_, k) => f.write_str(&format!("ScalarFieldEnum<{}>", k.join("."))),
            SynthesizedShapeReference::ScalarWhereWithAggregatesInput(_, k) => f.write_str(&format!("ScalarWhereWithAggregatesInput<{}>", k.join("."))),
            SynthesizedShapeReference::CountAggregateInputType(_, k) => f.write_str(&format!("CountAggregateInputType<{}>", k.join("."))),
            SynthesizedShapeReference::SumAggregateInputType(_, k) => f.write_str(&format!("SumAggregateInputType<{}>", k.join("."))),
            SynthesizedShapeReference::AvgAggregateInputType(_, k) => f.write_str(&format!("AvgAggregateInputType<{}>", k.join("."))),
            SynthesizedShapeReference::MaxAggregateInputType(_, k) => f.write_str(&format!("MaxAggregateInputType<{}>", k.join("."))),
            SynthesizedShapeReference::MinAggregateInputType(_, k) => f.write_str(&format!("MinAggregateInputType<{}>", k.join("."))),
            SynthesizedShapeReference::CreateInput(_, k) => f.write_str(&format!("CreateInput<{}>", k.join("."))),
            SynthesizedShapeReference::CreateInputWithout(_, k, r) => f.write_str(&format!("CreateInputWithout<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::CreateNestedOneInput(_, k) => f.write_str(&format!("CreateNestedOneInput<{}>", k.join("."))),
            SynthesizedShapeReference::CreateNestedOneInputWithout(_, k, r) => f.write_str(&format!("CreateNestedOneInputWithout<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::CreateNestedManyInput(_, k) => f.write_str(&format!("CreateNestedManyInput<{}>", k.join("."))),
            SynthesizedShapeReference::CreateNestedManyInputWithout(_, k, r) => f.write_str(&format!("CreateNestedManyInputWithout<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::UpdateInput(_, k) => f.write_str(&format!("UpdateInput<{}>", k.join("."))),
            SynthesizedShapeReference::UpdateInputWithout(_, k, r) => f.write_str(&format!("UpdateInputWithout<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::UpdateNestedOneInput(_, k) => f.write_str(&format!("UpdateNestedOneInput<{}>", k.join("."))),
            SynthesizedShapeReference::UpdateNestedOneInputWithout(_, k, r) => f.write_str(&format!("UpdateNestedOneInputWithout<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::UpdateNestedManyInput(_, k) => f.write_str(&format!("UpdateNestedManyInput<{}>", k.join("."))),
            SynthesizedShapeReference::UpdateNestedManyInputWithout(_, k, r) => f.write_str(&format!("UpdateNestedManyInputWithout<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::ConnectOrCreateInput(_, k) => f.write_str(&format!("ConnectOrCreateInput<{}>", k.join("."))),
            SynthesizedShapeReference::ConnectOrCreateInputWithout(_, k, r) => f.write_str(&format!("ConnectOrCreateInputWithout<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::UpdateWithWhereUniqueInput(_, k) => f.write_str(&format!("UpdateWithWhereUniqueInput<{}>", k.join("."))),
            SynthesizedShapeReference::UpdateWithWhereUniqueInputWithout(_, k, r) => f.write_str(&format!("UpdateWithWhereUniqueInput<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::UpsertWithWhereUniqueInput(_, k) => f.write_str(&format!("UpsertWithWhereUniqueInput<{}>", k.join("."))),
            SynthesizedShapeReference::UpsertWithWhereUniqueInputWithout(_, k, r) => f.write_str(&format!("UpsertWithWhereUniqueInput<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::UpdateManyWithWhereInput(_, k) => f.write_str(&format!("UpdateManyWithWhereInput<{}>", k.join("."))),
            SynthesizedShapeReference::UpdateManyWithWhereInputWithout(_, k, r) => f.write_str(&format!("UpdateManyWithWhereInput<{}, .{}>", k.join("."), r)),
            SynthesizedShapeReference::Select(_, k) => f.write_str(&format!("Select<{}>", k.join("."))),
            SynthesizedShapeReference::Include(_, k) => f.write_str(&format!("Include<{}>", k.join("."))),
            SynthesizedShapeReference::OrderByInput(_, k) => f.write_str(&format!("OrderByInput<{}>", k.join("."))),
            SynthesizedShapeReference::Result(_, k) => f.write_str(&format!("Result<{}>", k.join("."))),
            SynthesizedShapeReference::CountAggregateResult(_, k) => f.write_str(&format!("CountAggregateResult<{}>", k.join("."))),
            SynthesizedShapeReference::SumAggregateResult(_, k) => f.write_str(&format!("SumAggregateResult<{}>", k.join("."))),
            SynthesizedShapeReference::AvgAggregateResult(_, k) => f.write_str(&format!("AvgAggregateResult<{}>", k.join("."))),
            SynthesizedShapeReference::MinAggregateResult(_, k) => f.write_str(&format!("MinAggregateResult<{}>", k.join("."))),
            SynthesizedShapeReference::MaxAggregateResult(_, k) => f.write_str(&format!("MaxAggregateResult<{}>", k.join("."))),
            SynthesizedShapeReference::AggregateResult(_, k) => f.write_str(&format!("AggregateResult<{}>", k.join("."))),
            SynthesizedShapeReference::GroupByResult(_, k) => f.write_str(&format!("GroupByResult<{}>", k.join("."))),
        }
    }
}