use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use itertools::Itertools;
use crate::r#type::keyword::Keyword;
use serde::Serialize;
use teo_teon::Value;
use crate::ast::schema::Schema;

use crate::r#type::reference::Reference;
use crate::r#type::synthesized_shape::SynthesizedShape;
use crate::r#type::synthesized_enum_reference::SynthesizedEnumReference;
use crate::r#type::synthesized_enum::SynthesizedEnum;
use crate::r#type::synthesized_shape_reference::SynthesizedShapeReference;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize)]
pub enum Type {

    // default type

    /// Default type which is undetermined
    ///
    Undetermined,

    // special types

    /// Ignored
    ///
    Ignored,

    /// Any
    ///
    Any,

    /// Union
    ///
    Union(Vec<Type>),

    /// Enumerable
    ///
    Enumerable(Box<Type>),

    /// Optional
    ///
    Optional(Box<Type>),

    /// Field Type
    ///
    FieldType(Box<Type>, Box<Type>),

    /// Field Name
    ///
    FieldName(String),

    /// Generic Item
    ///
    GenericItem(String),

    /// Keyword
    ///
    Keyword(Keyword),

    // Teon types

    /// Null
    ///
    Null,

    /// Bool
    ///
    Bool,

    /// Int
    ///
    Int,

    /// Int64
    ///
    Int64,

    /// Float32
    ///
    Float32,

    /// Float
    ///
    Float,

    /// Decimal
    ///
    Decimal,

    /// String
    ///
    String,

    /// ObjectId is only available for MongoDB
    ///
    ObjectId,

    /// Date
    ///
    Date,

    /// DateTime
    ///
    DateTime,

    /// File
    ///
    File,

    /// Regex
    ///
    Regex,

    /// Array
    ///
    Array(Box<Type>),

    /// Dictionary
    ///
    Dictionary(Box<Type>),

    /// Tuple
    ///
    Tuple(Vec<Type>),

    /// Range
    ///
    Range(Box<Type>),

    // schema types

    /// Shape
    ///
    SynthesizedShape(SynthesizedShape),

    /// Synthesized Shape
    ///
    SynthesizedShapeReference(SynthesizedShapeReference),

    /// Enum Variant
    ///
    EnumVariant(Reference),

    /// Synthesized Enum Definition
    ///
    SynthesizedEnum(SynthesizedEnum),

    /// Synthesized Enum Reference
    ///
    SynthesizedEnumReference(SynthesizedEnumReference),

    /// Model
    ///
    Model,

    /// Model Object
    ModelObject(Reference),

    /// Interface Object
    ///
    InterfaceObject(Reference, Vec<Type>),

    /// Struct Object
    ///
    StructObject(Reference, Vec<Type>),

    /// Middleware
    ///
    Middleware,

    /// Data Set
    ///
    DataSet,

    /// Data Set Object
    ///
    DataSetObject(Vec<String>),

    /// Data Set Group
    ///
    DataSetGroup(Box<Type>),

    /// Data Set Record
    ///
    DataSetRecord(Box<Type>, Box<Type>),

    /// Pipeline
    ///
    Pipeline(Box<Type>, Box<Type>),
}

impl Type {

    pub fn is_undetermined(&self) -> bool {
        match self {
            Type::Undetermined => true,
            _ => false,
        }
    }

    pub fn is_ignored(&self) -> bool {
        match self {
            Type::Ignored => true,
            _ => false,
        }
    }

    pub fn is_any(&self) -> bool {
        match self {
            Type::Any => true,
            _ => false,
        }
    }

    pub fn is_union(&self) -> bool {
        self.as_union().is_some()
    }

    pub fn as_union(&self) -> Option<&Vec<Type>> {
        match self {
            Self::Union(types) => Some(types),
            _ => None,
        }
    }

    pub fn is_enumerable(&self) -> bool {
        self.as_enumerable().is_some()
    }

    pub fn as_enumerable(&self) -> Option<&Type> {
        match self {
            Self::Enumerable(inner) => Some(inner.as_ref()),
            _ => None,
        }
    }

    pub fn is_optional(&self) -> bool {
        self.as_optional().is_some()
    }

    pub fn as_optional(&self) -> Option<&Type> {
        match self {
            Type::Optional(t) => Some(t),
            _ => None,
        }
    }

    pub fn is_field_type(&self) -> bool {
        self.as_field_type().is_some()
    }

    pub fn as_field_type(&self) -> Option<(&Type, &Type)> {
        match self {
            Self::FieldType(path, field) => Some((path, field)),
            _ => None,
        }
    }

    pub fn is_field_name(&self) -> bool {
        self.as_field_name().is_some()
    }

    pub fn as_field_name(&self) -> Option<&str> {
        match self {
            Self::FieldName(name) => Some(name.as_str()),
            _ => None,
        }
    }

    pub fn is_generic_item(&self) -> bool {
        self.as_generic_item().is_some()
    }

    pub fn as_generic_item(&self) -> Option<&str> {
        match self {
            Self::GenericItem(name) => Some(name),
            _ => None,
        }
    }

    pub fn is_keyword(&self) -> bool {
        self.as_keyword().is_some()
    }

    pub fn as_keyword(&self) -> Option<&Keyword> {
        match self {
            Self::Keyword(kw) => Some(kw),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        match self {
            Type::Null => true,
            _ => false,
        }
    }

    pub fn is_bool(&self) -> bool {
        match self {
            Type::Bool => true,
            _ => false,
        }
    }

    pub fn is_int(&self) -> bool {
        match self {
            Type::Int => true,
            _ => false,
        }
    }

    pub fn is_int64(&self) -> bool {
        match self {
            Type::Int64 => true,
            _ => false,
        }
    }

    pub fn is_float32(&self) -> bool {
        match self {
            Type::Float32 => true,
            _ => false,
        }
    }

    pub fn is_float(&self) -> bool {
        match self {
            Type::Float => true,
            _ => false,
        }
    }

    pub fn is_decimal(&self) -> bool {
        match self {
            Type::Decimal => true,
            _ => false,
        }
    }

    pub fn is_string(&self) -> bool {
        match self {
            Type::String => true,
            _ => false,
        }
    }

    pub fn is_object_id(&self) -> bool {
        match self {
            Type::ObjectId => true,
            _ => false,
        }
    }

    pub fn is_date(&self) -> bool {
        match self {
            Type::Date => true,
            _ => false,
        }
    }

    pub fn is_datetime(&self) -> bool {
        match self {
            Type::DateTime => true,
            _ => false,
        }
    }

    pub fn is_file(&self) -> bool {
        match self {
            Type::File => true,
            _ => false,
        }
    }

    pub fn is_regex(&self) -> bool {
        match self {
            Type::Regex => true,
            _ => false,
        }
    }

    pub fn is_array(&self) -> bool {
        self.as_array().is_some()
    }

    pub fn as_array(&self) -> Option<&Type> {
        match self {
            Self::Array(inner) => Some(inner.as_ref()),
            _ => None,
        }
    }

    pub fn is_dictionary(&self) -> bool {
        self.as_dictionary().is_some()
    }

    pub fn as_dictionary(&self) -> Option<&Type> {
        match self {
            Self::Dictionary(v) => Some(v.as_ref()),
            _ => None,
        }
    }

    pub fn is_tuple(&self) -> bool {
        self.as_tuple().is_some()
    }

    pub fn as_tuple(&self) -> Option<&Vec<Type>> {
        match self {
            Self::Tuple(types) => Some(types),
            _ => None,
        }
    }

    pub fn is_range(&self) -> bool {
        self.as_range().is_some()
    }

    pub fn as_range(&self) -> Option<&Type> {
        match self {
            Self::Range(t) => Some(t.as_ref()),
            _ => None,
        }
    }

    pub fn is_synthesized_shape(&self) -> bool {
        self.as_synthesized_shape().is_some()
    }

    pub fn as_synthesized_shape(&self) -> Option<&SynthesizedShape> {
        match self {
            Type::SynthesizedShape(s) => Some(s),
            _ => None,
        }
    }

    pub fn into_synthesized_shape(self) -> Option<SynthesizedShape> {
        match self {
            Type::SynthesizedShape(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_synthesized_shape_reference(&self) -> bool {
        self.as_synthesized_shape_reference().is_some()
    }

    pub fn as_synthesized_shape_reference(&self) -> Option<&SynthesizedShapeReference> {
        match self {
            Type::SynthesizedShapeReference(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_enum_variant(&self) -> bool {
        self.as_enum_variant().is_some()
    }

    pub fn as_enum_variant(&self) -> Option<&Reference> {
        match self {
            Type::EnumVariant(a) => Some(a),
            _ => None,
        }
    }

    pub fn is_synthesized_enum(&self) -> bool {
        self.as_synthesized_enum().is_some()
    }

    pub fn as_synthesized_enum(&self) -> Option<&SynthesizedEnum> {
        match self {
            Type::SynthesizedEnum(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_synthesized_enum_reference(&self) -> bool {
        self.as_synthesized_enum_reference().is_some()
    }

    pub fn as_synthesized_enum_reference(&self) -> Option<&SynthesizedEnumReference> {
        match self {
            Type::SynthesizedEnumReference(e) => Some(e),
            _ => None,
        }
    }

    pub fn is_model(&self) -> bool {
        match self {
            Type::Model => true,
            _ => false,
        }
    }

    pub fn is_model_object(&self) -> bool {
        self.as_model_object().is_some()
    }

    pub fn as_model_object(&self) -> Option<&Reference> {
        match self {
            Type::ModelObject(r) => Some(r),
            _ => None,
        }
    }

    pub fn is_interface_object(&self) -> bool {
        self.as_interface_object().is_some()
    }

    pub fn as_interface_object(&self) -> Option<(&Reference, &Vec<Type>)> {
        match self {
            Type::InterfaceObject(r, g) => Some((r, g)),
            _ => None,
        }
    }

    pub fn is_struct_object(&self) -> bool {
        self.as_struct_object().is_some()
    }

    pub fn as_struct_object(&self) -> Option<(&Reference, &Vec<Type>)> {
        match self {
            Type::StructObject(r, g) => Some((r, g)),
            _ => None,
        }
    }

    pub fn is_middleware(&self) -> bool {
        match self {
            Type::Middleware => true,
            _ => false,
        }
    }

    pub fn is_data_set(&self) -> bool {
        match self {
            Type::DataSet => true,
            _ => false,
        }
    }

    pub fn is_data_set_object(&self) -> bool {
        self.as_data_set_object().is_some()
    }

    pub fn as_data_set_object(&self) -> Option<&Vec<String>> {
        match self {
            Type::DataSetObject(path) => Some(path),
            _ => None,
        }
    }

    pub fn is_data_set_group(&self) -> bool {
        self.as_data_set_group().is_some()
    }

    pub fn as_data_set_group(&self) -> Option<&Type> {
        match self {
            Type::DataSetGroup(r) => Some(r.as_ref()),
            _ => None,
        }
    }

    pub fn is_data_set_record(&self) -> bool {
        self.as_data_set_record().is_some()
    }

    pub fn as_data_set_record(&self) -> Option<(&Type, &Type)> {
        match self {
            Self::DataSetRecord(a, b) => Some((a.as_ref(), b.as_ref())),
            _ => None,
        }
    }

    pub fn is_pipeline(&self) -> bool {
        self.as_pipeline().is_some()
    }

    pub fn as_pipeline(&self) -> Option<(&Type, &Type)> {
        match self {
            Type::Pipeline(a, b) => Some((a.as_ref(), b.as_ref())),
            _ => None,
        }
    }

    pub fn wrap_in_array(&self) -> Type {
        Type::Array(Box::new(self.clone()))
    }

    pub fn wrap_in_enumerable(&self) -> Type {
        if self.is_enumerable() {
            self.clone()
        } else {
            Type::Enumerable(Box::new(self.clone()))
        }
    }

    pub fn wrap_in_optional(&self) -> Type {
        if self.is_optional() {
            self.clone()
        } else {
            Type::Optional(Box::new(self.clone()))
        }
    }

    pub fn unwrap_optional(&self) -> &Type {
        if self.is_optional() {
            self.as_optional().unwrap()
        } else {
            self
        }
    }

    pub fn unwrap_array(&self) -> &Type {
        if self.is_array() {
            self.as_array().unwrap()
        } else {
            self
        }
    }

    pub fn unwrap_enumerable(&self) -> &Type {
        if self.is_enumerable() {
            self.as_enumerable().unwrap()
        } else {
            self
        }
    }

    pub fn unwrap_dictionary(&self) -> &Type {
        if self.is_dictionary() {
            self.as_dictionary().unwrap()
        } else {
            self
        }
    }

    pub fn unwrap_tuple_index(&self, index: usize) -> Option<&Type> {
        if self.is_tuple() {
            self.as_tuple().unwrap().get(index )
        } else {
            None
        }
    }

    pub fn is_int_32_or_64(&self) -> bool {
        match self {
            Type::Int | Type::Int64 => true,
            _ => false,
        }
    }

    pub fn is_float_32_or_64(&self) -> bool {
        match self {
            Type::Float32 | Type::Float => true,
            _ => false,
        }
    }

    pub fn is_any_int_or_float(&self) -> bool {
        self.is_int_32_or_64() || self.is_float_32_or_64()
    }

    pub fn is_any_number(&self) -> bool {
        self.is_any_int_or_float() || self.is_decimal()
    }

    pub fn expect_for_literal(&self) -> Type {
        self.unwrap_optional().clone()
    }

    pub fn expect_for_enum_variant_literal(&self) -> Type {
        let mut result = self;
        if result.is_optional() {
            result = result.unwrap_optional();
        }
        if result.is_enumerable() {
            result = result.unwrap_enumerable();
        }
        if result.is_optional() {
            result = result.unwrap_optional();
        }
        if let Some(union) = result.as_union() {
            for result in union {
                if result.is_enum_variant() || result.is_synthesized_enum() || result.is_synthesized_enum_reference() || result.is_data_set_record() {
                    return result.clone();
                }
            }
        }
        if result.is_enum_variant() || result.is_synthesized_enum() || result.is_synthesized_enum_reference() || result.is_data_set_record() {
            result.clone()
        } else {
            result.clone()
        }
    }

    pub fn expect_for_tuple_literal(&self) -> Type {
        let mut result = self;
        if result.is_optional() {
            result = result.unwrap_optional();
        }
        if result.is_tuple() {
            return result.clone();
        }
        result.clone()
    }

    pub fn expect_for_array_literal(&self) -> Type {
        let mut result = self;
        if result.is_optional() {
            result = result.unwrap_optional();
        }
        if result.is_array() {
            return result.clone();
        }
        if result.is_enumerable() {
            return Type::Array(Box::new(result.as_enumerable().unwrap().clone()));
        }
        return result.clone()
    }

    pub fn expect_for_dictionary_literal(&self) -> Type {
        let mut result = self;
        if result.is_optional() {
            result = result.unwrap_optional();
        }
        if result.is_dictionary() {
            return result.clone();
        }
        return result.clone()
    }

    pub fn contains_generics(&self) -> bool {
        match self {
            Type::GenericItem(_) => true,
            Type::Union(types) => types.iter().any(|t| t.contains_generics()),
            Type::Enumerable(inner) => inner.contains_generics(),
            Type::Optional(inner) => inner.contains_generics(),
            Type::FieldType(a, b) => a.contains_generics() || b.contains_generics(),
            Type::Array(inner) => inner.contains_generics(),
            Type::Dictionary(inner) => inner.contains_generics(),
            Type::Tuple(types) => types.iter().any(|t| t.contains_generics()),
            Type::Range(inner) => inner.contains_generics(),
            Type::SynthesizedShape(shape) => !shape.generics().is_empty(),
            Type::InterfaceObject(_, types) => types.iter().any(|t| t.contains_generics()),
            Type::StructObject(_, types) => types.iter().any(|t| t.contains_generics()),
            Type::DataSetGroup(inner) => inner.contains_generics(),
            Type::DataSetRecord(a, b) => a.contains_generics() || b.contains_generics(),
            Type::Pipeline(a, b) => a.contains_generics() || b.contains_generics(),
            _ => false,
        }
    }

    pub fn contains_keywords(&self) -> bool {
        match self {
            Type::GenericItem(_) => true,
            Type::Union(types) => types.iter().any(|t| t.contains_keywords()),
            Type::Enumerable(inner) => inner.contains_keywords(),
            Type::Optional(inner) => inner.contains_keywords(),
            Type::FieldType(a, b) => a.contains_keywords() || b.contains_keywords(),
            Type::Array(inner) => inner.contains_keywords(),
            Type::Dictionary(inner) => inner.contains_keywords(),
            Type::Tuple(types) => types.iter().any(|t| t.contains_keywords()),
            Type::Range(inner) => inner.contains_keywords(),
            Type::SynthesizedShape(shape) => !shape.generics().is_empty(),
            Type::InterfaceObject(_, types) => types.iter().any(|t| t.contains_keywords()),
            Type::StructObject(_, types) => types.iter().any(|t| t.contains_keywords()),
            Type::DataSetGroup(inner) => inner.contains_keywords(),
            Type::DataSetRecord(a, b) => a.contains_keywords() || b.contains_keywords(),
            Type::Pipeline(a, b) => a.contains_keywords() || b.contains_keywords(),
            _ => false,
        }
    }

    pub fn replace_generics(&self, map: &BTreeMap<String, Type>) -> Self {
        match self {
            Type::GenericItem(name) => if let Some(t) = map.get(name) {
                t.clone()
            } else {
                self.clone()
            },
            Type::Union(types) => Type::Union(types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::Enumerable(inner) => Type::Enumerable(Box::new(inner.replace_generics(map))),
            Type::Optional(inner) => Type::Optional(Box::new(inner.replace_generics(map))),
            Type::FieldType(a, b) => Type::FieldType(
                Box::new(a.replace_generics(map)),
                Box::new(b.replace_generics(map)),
            ),
            Type::Array(inner) => Type::Array(Box::new(inner.replace_generics(map))),
            Type::Dictionary(inner) => Type::Dictionary(Box::new(inner.replace_generics(map))),
            Type::Tuple(types) => Type::Tuple(types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::Range(inner) => Type::Range(Box::new(inner.replace_generics(map))),
            Type::SynthesizedShapeReference(shape_reference) => Type::SynthesizedShapeReference(shape_reference.replace_generics(map)),
            Type::SynthesizedEnumReference(enum_reference) => Type::SynthesizedEnumReference(enum_reference.replace_generics(map)),
            Type::SynthesizedShape(shape) => Type::SynthesizedShape(shape.replace_generics(map)),
            Type::InterfaceObject(r, types) => Type::InterfaceObject(r.clone(), types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::StructObject(r, types) => Type::StructObject(r.clone(), types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::DataSetGroup(inner) => Type::DataSetGroup(Box::new(inner.replace_generics(map))),
            Type::DataSetRecord(a, b) => Type::DataSetRecord(
                Box::new(a.replace_generics(map)),
                Box::new(b.replace_generics(map)),
            ),
            Type::Pipeline(a, b) => Type::Pipeline(
                Box::new(a.replace_generics(map)),
                Box::new(b.replace_generics(map)),
            ),
            _ => self.clone(),
        }
    }

    pub fn replace_keywords(&self, map: &BTreeMap<Keyword, Type>) -> Self {
        match self {
            Type::Keyword(name) => if let Some(t) = map.get(name) {
                t.clone()
            } else {
                self.clone()
            },
            Type::Union(types) => Type::Union(types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::Enumerable(inner) => Type::Enumerable(Box::new(inner.replace_keywords(map))),
            Type::Optional(inner) => Type::Optional(Box::new(inner.replace_keywords(map))),
            Type::FieldType(a, b) => Type::FieldType(
                Box::new(a.replace_keywords(map)),
                Box::new(b.replace_keywords(map)),
            ),
            Type::Array(inner) => Type::Array(Box::new(inner.replace_keywords(map))),
            Type::Dictionary(inner) => Type::Dictionary(Box::new(inner.replace_keywords(map))),
            Type::Tuple(types) => Type::Tuple(types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::Range(inner) => Type::Range(Box::new(inner.replace_keywords(map))),
            Type::SynthesizedShapeReference(shape_reference) => Type::SynthesizedShapeReference(shape_reference.replace_keywords(map)),
            Type::SynthesizedEnumReference(enum_reference) => Type::SynthesizedEnumReference(enum_reference.replace_keywords(map)),
            Type::SynthesizedShape(shape) => Type::SynthesizedShape(shape.replace_keywords(map)),
            Type::InterfaceObject(r, types) => Type::InterfaceObject(r.clone(), types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::StructObject(r, types) => Type::StructObject(r.clone(), types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::DataSetGroup(inner) => Type::DataSetGroup(Box::new(inner.replace_keywords(map))),
            Type::DataSetRecord(a, b) => Type::DataSetRecord(
                Box::new(a.replace_keywords(map)),
                Box::new(b.replace_keywords(map)),
            ),
            Type::Pipeline(a, b) => Type::Pipeline(
                Box::new(a.replace_keywords(map)),
                Box::new(b.replace_keywords(map)),
            ),
            _ => self.clone(),
        }
    }

    /// Return `true` if `other` satisfies `self`
    ///
    pub fn test(&self, other: &Type) -> bool {
        match self {
            Type::Undetermined => false,
            Type::Ignored => true,
            Type::Any => true,
            Type::Union(types) => types.iter().any(|t| t.test(other)),
            Type::Enumerable(inner) => inner.test(other) || Type::Array(inner.clone()).test(other),
            Type::Optional(inner) => inner.test(other) || (other.is_optional() && inner.test(other.as_optional().unwrap())),
            Type::FieldType(a, b) => other.is_field_type() && a.test(other.as_field_type().unwrap().0) && b.test(other.as_field_type().unwrap().1),
            Type::FieldName(_) => other.is_field_name(),
            Type::GenericItem(_) => true,
            Type::Keyword(k) => other.is_keyword() && k == other.as_keyword().unwrap(),
            Type::Null => other.is_null(),
            Type::Bool => other.is_bool(),
            Type::Int => other.is_int(),
            Type::Int64 => other.is_int64(),
            Type::Float32 => other.is_float32(),
            Type::Float => other.is_float(),
            Type::Decimal => other.is_decimal(),
            Type::String => other.is_string(),
            Type::ObjectId => other.is_object_id(),
            Type::Date => other.is_date(),
            Type::DateTime => other.is_datetime(),
            Type::File => other.is_file(),
            Type::Regex => other.is_regex(),
            Type::Array(inner) => other.is_array() && inner.as_ref().test(other.as_array().unwrap()),
            Type::Dictionary(inner) => other.is_dictionary() && inner.as_ref().test(other.as_dictionary().unwrap()),
            Type::Tuple(types) => other.is_tuple() && other.as_tuple().unwrap().len() == types.len() && types.iter().enumerate().all(|(index, t)| t.test(other.as_tuple().unwrap().get(index).unwrap())),
            Type::Range(inner) => other.is_range() && inner.as_ref().test(other.as_range().unwrap()),
            Type::SynthesizedShape(shape) => other.is_synthesized_shape() && shape.test(other.as_synthesized_shape().unwrap()),
            Type::SynthesizedShapeReference(r) => other.is_synthesized_shape_reference() && r == other.as_synthesized_shape_reference().unwrap(),
            Type::EnumVariant(r) => other.is_enum_variant() && r == other.as_enum_variant().unwrap(),
            Type::SynthesizedEnum(s) => other.is_synthesized_enum() && s.members.keys().collect::<BTreeSet<&String>>() == other.as_synthesized_enum().unwrap().members.keys().collect::<BTreeSet<&String>>(),
            Type::SynthesizedEnumReference(r) => other.is_synthesized_enum_reference() && r == other.as_synthesized_enum_reference().unwrap(),
            Type::Model => other.is_model(),
            Type::ModelObject(r) => other.is_model_object() && r == other.as_model_object().unwrap(),
            Type::InterfaceObject(r, types) => other.is_interface_object() && r == other.as_interface_object().unwrap().0 && other.as_interface_object().unwrap().1.len() == types.len() && types.iter().enumerate().all(|(index, t)| t.test(other.as_interface_object().unwrap().1.get(index).unwrap())),
            Type::StructObject(r, types) => other.is_struct_object() && r == other.as_struct_object().unwrap().0 && other.as_struct_object().unwrap().1.len() == types.len() && types.iter().enumerate().all(|(index, t)| t.test(other.as_struct_object().unwrap().1.get(index).unwrap())),
            Type::Middleware => other.is_middleware(),
            Type::DataSet => other.is_data_set(),
            Type::DataSetObject(r) => other.is_data_set_object() && r == other.as_data_set_object().unwrap(),
            Type::DataSetGroup(inner) => other.is_data_set_group() && inner.test(other.as_data_set_group().unwrap()),
            Type::DataSetRecord(a, b) => other.is_data_set_record() && a.test(other.as_data_set_record().unwrap().0) && b.test(other.as_data_set_record().unwrap().1),
            Type::Pipeline(a, b) => other.is_pipeline() && a.test(other.as_pipeline().unwrap().0) && b.test(other.as_pipeline().unwrap().1),
        }
    }

    pub fn constraint_test(&self, other: &Type, schema: &Schema) -> (bool, bool) {
        if self.is_model() && other.is_model_object() {
            (true, true)
        } else if self.is_synthesized_enum_reference() && other.is_field_name() {
            let synthesized_enum_reference = self.as_synthesized_enum_reference().unwrap();
            if let Some(definition) = synthesized_enum_reference.fetch_synthesized_definition(schema) {
                let result = definition.members.keys().contains(&other.as_field_name().unwrap().to_string());
                (result, true)
            } else {
                (false, true)
            }
        } else {
            let result = self.test(other);
            (result, result)
        }
    }

    pub fn flatten(&self) -> Type {
        if let Some(inner) = self.as_optional() {
            if inner.is_optional() {
                return inner.flatten();
            }
        }
        self.clone()
    }

    pub fn replace_field_type<F>(&self, f: F) -> Type where F: Fn(&Type, &Type) -> Type {
        let f_ref = |t: &Type, f: &dyn Fn(&Type, &Type) -> Type| { t.replace_field_type(f) };
        match self {
            Type::Enumerable(t) => Type::Enumerable(Box::new(f_ref(t, &f))),
            Type::Array(t) => Type::Array(Box::new(f_ref(t, &f))),
            Type::Dictionary(t) => Type::Dictionary(Box::new(f_ref(t, &f))),
            Type::Tuple(types) => Type::Tuple(types.iter().map(|t| f_ref(t, &f)).collect()),
            Type::Range(t) => Type::Range(Box::new(f_ref(t, &f))),
            Type::Union(types) => Type::Union(types.iter().map(|t| f_ref(t, &f)).collect()),
            Type::FieldType(a, b) => f(a.as_ref(), b.as_ref()),
            Type::Optional(t) => Type::Optional(Box::new(f_ref(t, &f))),
            Type::Pipeline(t1, t2) => Type::Pipeline(Box::new(f_ref(t1, &f)), Box::new(f_ref(t2, &f))),
            Type::InterfaceObject(r, types) => Type::InterfaceObject(r.clone(), types.iter().map(|t| f_ref(t, &f)).collect()),
            Type::StructObject(r, types) => Type::StructObject(r.clone(), types.iter().map(|t| f_ref(t, &f)).collect()),
            Type::DataSetGroup(inner) => Type::DataSetGroup(Box::new(f_ref(inner, &f))),
            Type::DataSetRecord(a, b) => Type::DataSetRecord(
                Box::new(f_ref(a, &f)),
                Box::new(f_ref(b, &f)),
            ),
            _ => self.clone(),
        }
    }

    pub fn generic_types(&self) -> Vec<Type> {
        match self {
            Type::Optional(inner) => vec![inner.as_ref().clone()],
            Type::Array(inner) => vec![inner.as_ref().clone()],
            Type::Dictionary(inner) => vec![inner.as_ref().clone()],
            Type::Tuple(types) => types.clone(),
            Type::Range(inner) => vec![inner.as_ref().clone()],
            Type::InterfaceObject(_, types) => types.clone(),
            Type::StructObject(_, types) => types.clone(),
            Type::Pipeline(input, output) => vec![input.as_ref().clone(), output.as_ref().clone()],
            _ => vec![]
        }
    }

    pub fn can_coerce_to(&self, other: &Type) -> bool {
        if self == other {
            true
        } else if self.is_int() && other.is_int64() {
            true
        } else if self.is_int64() && other.is_int() {
            true
        } else if self.is_float32() && other.is_float() {
            true
        } else if self.is_float() && other.is_float32() {
            true
        } else if self.is_int_32_or_64() && other.is_float_32_or_64() {
            true
        } else if !self.is_optional() && other.is_optional() {
            self.can_coerce_to(other.as_optional().unwrap())
        } else if self.is_optional() && other.is_optional() {
            self.as_optional().unwrap().can_coerce_to(other.as_optional().unwrap())
        } else if self.is_enumerable() && other.is_enumerable() {
            self.as_enumerable().unwrap().can_coerce_to(other.as_enumerable().unwrap())
        } else if self.is_array() && other.is_enumerable() {
            self.as_array().unwrap().can_coerce_to(other.as_enumerable().unwrap())
        } else if !self.is_enumerable() && other.is_enumerable() {
            self.can_coerce_to(other.as_enumerable().unwrap())
        } else {
            false
        }
    }

    pub fn coerce_value_to(&self, value: &Value, other: &Type) -> Option<Value> {
        if self == other || other.test(self) {
            Some(value.clone())
        } else if other.unwrap_optional().unwrap_enumerable().unwrap_optional().is_float() {
            value.to_float().map(|f| Value::Float(f))
        } else if other.unwrap_optional().unwrap_enumerable().unwrap_optional().is_float32() {
            value.to_float32().map(|f| Value::Float32(f))
        } else if other.unwrap_optional().unwrap_enumerable().unwrap_optional().is_int() {
            value.to_int().map(|f| Value::Int(f))
        } else if other.unwrap_optional().unwrap_enumerable().unwrap_optional().is_int64() {
            value.to_int64().map(|f| Value::Int64(f))
        } else {
            None
        }
    }

    pub fn flatten_struct_into_primitive(&self) -> Type {
        if let Some((reference, types)) = self.as_struct_object() {
            if reference.str_path() == vec!["std", "Null"] {
                Type::Null
            } else if reference.str_path() == vec!["std", "Bool"] {
                Type::Bool
            } else if reference.str_path() == vec!["std", "Int"] {
                Type::Int
            } else if reference.str_path() == vec!["std", "Int64"] {
                Type::Int64
            } else if reference.str_path() == vec!["std", "Float32"] {
                Type::Float32
            } else if reference.str_path() == vec!["std", "Float"] {
                Type::Float
            } else if reference.str_path() == vec!["std", "Decimal"] {
                Type::Decimal
            } else if reference.str_path() == vec!["std", "String"] {
                Type::String
            } else if reference.str_path() == vec!["std", "ObjectId"] {
                Type::ObjectId
            } else if reference.str_path() == vec!["std", "Date"] {
                Type::Date
            } else if reference.str_path() == vec!["std", "DateTime"] {
                Type::DateTime
            } else if reference.str_path() == vec!["std", "File"] {
                Type::File
            } else if reference.str_path() == vec!["std", "Regex"] {
                Type::Regex
            } else if reference.str_path() == vec!["std", "Array"] {
                Type::Array(Box::new(types.get(0).unwrap().clone()))
            } else if reference.str_path() == vec!["std", "Dictionary"] {
                Type::Dictionary(Box::new(types.get(0).unwrap().clone()))
            } else if reference.str_path() == vec!["std", "Range"] {
                Type::Range(Box::new(types.get(0).unwrap().clone()))
            } else {
                self.clone()
            }
        } else {
            self.clone()
        }
    }
}

impl Display for Type {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::Undetermined => f.write_str("Undetermined"),
            Type::Ignored => f.write_str("Ignored"),
            Type::Any => f.write_str("Any"),
            Type::Union(types) => f.write_str(&types.iter().map(|t| format!("{t}")).join(" | ")),
            Type::Enumerable(inner) => f.write_str(&format!("Enumerable<{}>", inner)),
            Type::Optional(inner) => if inner.is_union() {
                f.write_str(&format!("({})?", inner))
            } else {
                f.write_str(&format!("{}?", inner))
            },
            Type::FieldType(a, b) => if a.is_union() {
                f.write_str(&format!("({})[{}]", a, b))
            } else {
                f.write_str(&format!("{}[{}]", a, b))
            },
            Type::FieldName(name) => f.write_str(&format!(".{}", name)),
            Type::GenericItem(name) => f.write_str(name),
            Type::Keyword(k) => Display::fmt(k, f),
            Type::Null => f.write_str("Null"),
            Type::Bool => f.write_str("Bool"),
            Type::Int => f.write_str("Int"),
            Type::Int64 => f.write_str("Int64"),
            Type::Float32 => f.write_str("Float32"),
            Type::Float => f.write_str("Float"),
            Type::Decimal => f.write_str("Decimal"),
            Type::String => f.write_str("String"),
            Type::ObjectId => f.write_str("ObjectId"),
            Type::Date => f.write_str("Date"),
            Type::DateTime => f.write_str("DateTime"),
            Type::File => f.write_str("File"),
            Type::Regex => f.write_str("Regex"),
            Type::Array(inner) => if inner.is_union() {
                f.write_str(&format!("({})[]", inner))
            } else {
                f.write_str(&format!("{}[]", inner))
            },
            Type::Dictionary(inner) => if inner.is_union() {
                f.write_str(&format!("({}){{}}", inner))
            } else {
                f.write_str(&format!("{}{{}}", inner))
            }
            Type::Tuple(types) => {
                f.write_str("(")?;
                let len = types.len();
                for (index, t) in types.iter().enumerate() {
                    Display::fmt(t, f)?;
                    if index != len - 1 {
                        f.write_str(", ")?;
                    }
                }
                if len == 1 {
                    f.write_str(",")?;
                }
                f.write_str(")")
            },
            Type::Range(inner) => f.write_str(&format!("Range<{}>", inner)),
            Type::SynthesizedShape(shape) => Display::fmt(shape, f),
            Type::SynthesizedShapeReference(r) => Display::fmt(r, f),
            Type::EnumVariant(r) => f.write_str(&r.string_path().join(".")),
            Type::SynthesizedEnum(e) => Display::fmt(e, f),
            Type::SynthesizedEnumReference(r) => f.write_str(&format!("{}", r)),
            Type::Model => f.write_str("Model"),
            Type::ModelObject(r) => f.write_str(&r.string_path().join(".")),
            Type::InterfaceObject(r, t) => if t.is_empty() {
                f.write_str(&format!("{}", &r.string_path().join(".")))
            } else {
                f.write_str(&format!("{}<{}>", &r.string_path().join("."), t.iter().map(|t| format!("{t}")).join(", ")))
            }
            Type::StructObject(r, t) => if t.is_empty() {
                f.write_str(&format!("{}", &r.string_path().join(".")))
            } else {
                f.write_str(&format!("{}<{}>", &r.string_path().join("."), t.iter().map(|t| format!("{t}")).join(", ")))
            },
            Type::Middleware => f.write_str("Middleware"),
            Type::DataSet => f.write_str("DataSet"),
            Type::DataSetObject(r) => f.write_str(&format!("DataSetObject<{}>", r.join("."))),
            Type::DataSetGroup(inner) => f.write_str(&format!("DataSetGroup<{}>", inner)),
            Type::DataSetRecord(a, b) => f.write_str(&format!("DataSetRecord<{}, {}>", a, b)),
            Type::Pipeline(i, o) => f.write_str(&format!("Pipeline<{}, {}>", i, o)),
        }
    }
}
