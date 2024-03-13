use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use serde::Serialize;
use crate::r#type::Type;
use strum_macros::{Display, EnumString, AsRefStr, EnumIter};
use crate::ast::schema::Schema;
use crate::r#type::keyword::Keyword;
use crate::r#type::reference::Reference;

use crate::traits::resolved::Resolve;

#[derive(Debug, Copy, Clone, Eq, Hash, PartialEq, Serialize, Display, EnumString, AsRefStr, EnumIter)]
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
    ScalarUpdateInput,
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

    pub fn fetch_synthesized_definition<'a>(&self, schema: &'a Schema) -> Option<&'a Type> {
        let model = schema.find_top_by_path(self.owner.as_model_object().unwrap().path()).unwrap().as_model().unwrap();
        model.resolved().shapes.get(&(self.kind, self.without.clone()))
    }

    pub fn args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::Args,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn find_many_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::FindManyArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn find_first_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::FindFirstArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn find_unique_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::FindUniqueArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn create_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CreateArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn update_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn upsert_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpsertArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn copy_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CopyArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn delete_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::DeleteArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn create_many_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CreateManyArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn update_many_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateManyArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn copy_many_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CopyManyArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn delete_many_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::DeleteManyArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn count_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CountArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn aggregate_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::AggregateArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn group_by_args(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::GroupByArgs,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn relation_filter(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::RelationFilter,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn list_relation_filter(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::ListRelationFilter,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn where_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::WhereInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn where_unique_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::WhereUniqueInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn scalar_where_with_aggregates_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::ScalarWhereWithAggregatesInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn count_aggregate_input_type(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CountAggregateInputType,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn sum_aggregate_input_type(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::SumAggregateInputType,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn avg_aggregate_input_type(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::AvgAggregateInputType,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn max_aggregate_input_type(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::MaxAggregateInputType,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn min_aggregate_input_type(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::MinAggregateInputType,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn create_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CreateInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn create_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CreateInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn create_nested_one_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CreateNestedOneInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn create_nested_one_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CreateNestedOneInputWithout,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn create_nested_many_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CreateNestedManyInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn create_nested_many_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CreateNestedManyInputWithout,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn update_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn update_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn update_nested_one_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateNestedOneInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn update_nested_one_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateNestedOneInputWithout,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn update_nested_many_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateNestedManyInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn update_nested_many_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateNestedManyInputWithout,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn connect_or_create_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::ConnectOrCreateInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn connect_or_create_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::ConnectOrCreateInputWithout,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn update_with_where_unique_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateWithWhereUniqueInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn update_with_where_unique_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateWithWhereUniqueInputWithout,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn upsert_with_where_unique_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpsertWithWhereUniqueInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn upsert_with_where_unique_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpsertWithWhereUniqueInputWithout,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn update_many_with_where_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateManyWithWhereInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn update_many_with_where_input_without(reference: Reference, without: String) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::UpdateManyWithWhereInputWithout,
            owner: Box::new(Type::ModelObject(reference)),
            without: Some(without)
        }
    }

    pub fn select(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::Select,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn include(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::Include,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn order_by_input(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::OrderByInput,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn result(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::Result,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn count_aggregate_result(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::CountAggregateResult,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn sum_aggregate_result(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::SumAggregateResult,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn avg_aggregate_result(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::AvgAggregateResult,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn min_aggregate_result(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::MinAggregateResult,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn max_aggregate_result(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::MaxAggregateResult,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn aggregate_result(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::AggregateResult,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn group_by_result(reference: Reference) -> Self {
        Self {
            kind: SynthesizedShapeReferenceKind::GroupByResult,
            owner: Box::new(Type::ModelObject(reference)),
            without: None
        }
    }

    pub fn replace_keywords(&self, map: &BTreeMap<Keyword, Type>) -> Self {
        Self {
            kind: self.kind,
            owner: Box::new(self.owner.replace_keywords(map)),
            without: self.without.clone(),
        }
    }

    pub fn replace_generics(&self, map: &BTreeMap<String, Type>) -> Self {
        Self {
            kind: self.kind,
            owner: Box::new(self.owner.replace_generics(map)),
            without: self.without.clone(),
        }
    }

    pub fn build_generics_map(&self, map: &mut BTreeMap<String, Type>, expect: &SynthesizedShapeReference) {
        self.owner.build_generics_map(map, expect.owner.as_ref());
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