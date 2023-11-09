use std::fmt::{Display, Formatter};
use serde::Serialize;
use crate::r#type::Type;
use strum_macros::{Display, EnumString, AsRefStr};
use crate::ast::schema::Schema;
use crate::r#type::synthesized_shape::SynthesizedShape;

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Serialize, Display, EnumString, AsRefStr)]
pub enum SynthesizedShapeReferenceKind {
    Args,
    FindManyArgs,
    FindFirstArgs,
    FindUniqueArgs,
    CreateArgs,
    UpdateArgs,
    UpsertArgs,
    CopyArgs,
    DeleteArgs,
    CreateManyArgs,
    UpdateManyArgs,
    CopyManyArgs,
    DeleteManyArgs,
    CountArgs,
    AggregateArgs,
    GroupByArgs,
    RelationFilter,
    ListRelationFilter,
    WhereInput,
    WhereUniqueInput,
    ScalarFieldEnum,
    ScalarWhereWithAggregatesInput,
    CountAggregateInputType,
    SumAggregateInputType,
    AvgAggregateInputType,
    MaxAggregateInputType,
    MinAggregateInputType,
    CreateInput,
    CreateInputWithout,
    CreateNestedOneInput,
    CreateNestedOneInputWithout,
    CreateNestedManyInput,
    CreateNestedManyInputWithout,
    UpdateInput,
    UpdateInputWithout,
    UpdateNestedOneInput,
    UpdateNestedOneInputWithout,
    UpdateNestedManyInput,
    UpdateNestedManyInputWithout,
    ConnectOrCreateInput,
    ConnectOrCreateInputWithout,
    UpdateWithWhereUniqueInput,
    UpdateWithWhereUniqueInputWithout,
    UpsertWithWhereUniqueInput,
    UpsertWithWhereUniqueInputWithout,
    UpdateManyWithWhereInput,
    UpdateManyWithWhereInputWithout,
    Select,
    Include,
    OrderByInput,
    Result,
    CountAggregateResult,
    SumAggregateResult,
    AvgAggregateResult,
    MinAggregateResult,
    MaxAggregateResult,
    AggregateResult,
    GroupByResult,
}

impl SynthesizedShapeReferenceKind {

    pub fn requires_without(&self) -> bool {
        self.as_ref().ends_with("Without")
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq, Serialize)]
pub struct SynthesizedShapeReference {
    pub kind: SynthesizedShapeReferenceKind,
    pub owner: Box<Type>,
    pub without: Option<String>,
}

impl SynthesizedShapeReference {

    pub fn fetch_synthesized_definition(&self, schema: &Schema) -> Option<&Type> {
        let model = schema.find_top_by_path(self.owner.as_model_object().unwrap().path()).unwrap().as_model().unwrap();
        model.resolved().shapes.get(&(self.kind, self.without.clone()))
    }
}

impl Display for SynthesizedShapeReference {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{}<{}{}>", self.kind, self.owner, if let Some(without) = self.without.as_ref() {
            format!(", .{}", without)
        } else {
            "".to_owned()
        }))
    }
}