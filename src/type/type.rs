use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use itertools::Itertools;
use crate::r#type::keyword::Keyword;
use educe::Educe;
use serde::Serialize;
use crate::r#type::reference::Reference;
use crate::r#type::shape::SynthesizedShape;
use crate::r#type::synthesized_enum_reference::SynthesizedEnumReference;
use crate::r#type::synthesized_enum::SynthesizedEnum;
use crate::r#type::synthesized_shape_reference::SynthesizedShapeReference;

#[derive(Debug, Clone, Eq, Serialize)]
#[derive(Educe)]
#[educe(Hash, PartialEq)]
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

    /// Field Reference
    ///
    FieldReference(String),

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

    /// Enum
    ///
    Enum,

    /// Enum Reference
    ///
    EnumReference(Reference),

    /// Enum Variant
    ///
    EnumVariant(Reference),

    /// Synthesized Enum Definition
    ///
    SynthesizedEnum(SynthesizedEnum),


    /// Synthesized Enum Reference
    ///
    SynthesizedEnumReference(SynthesizedEnumReference),

    /// Synthesized Enum Variant Reference
    ///
    SynthesizedEnumVariantReference(SynthesizedEnumReference),

    /// Model
    ///
    Model,

    /// Model Reference
    ///
    ModelReference(Reference),

    /// Model Object
    ModelObject(Reference),

    /// Interface
    ///
    InterfaceReference(Reference, Vec<Type>),

    /// Interface Object
    ///
    InterfaceObject(Reference, Vec<Type>),

    /// Struct
    ///
    StructReference(Reference, Vec<Type>),

    /// Struct Object
    ///
    StructObject(Reference, Vec<Type>),

    /// Struct Static Function
    ///
    StructStaticFunctionReference(Reference, Vec<Type>),

    /// Struct Static Function
    ///
    StructInstanceFunctionReference(Reference, Vec<Type>),

    /// Function
    ///
    /// These functions are declared outside of structs
    ///
    FunctionReference(Reference),

    /// Middleware
    ///
    Middleware,

    /// Middleware Reference
    ///
    MiddlewareReference(Reference),

    /// Data Set
    ///
    DataSet,

    /// Data Set Object
    DataSetReference(Reference),

    /// Data Set Group
    ///
    DataSetGroup(Box<Type>),

    /// Data Set Record
    ///
    DataSetRecord(Box<Type>, Box<Type>),

    /// Namespace
    ///
    Namespace,

    /// Namespace Reference
    ///
    NamespaceReference(Reference),

    /// Pipeline
    ///
    Pipeline((Box<Type>, Box<Type>)),
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

    pub fn is_field_reference(&self) -> bool {
        self.as_field_reference().is_some()
    }

    pub fn as_field_reference(&self) -> Option<&str> {
        match self {
            Self::FieldReference(name) => Some(name.as_str()),
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

    pub fn is_synthesized_shape_reference(&self) -> bool {
        self.as_synthesized_shape_reference().is_some()
    }

    pub fn as_synthesized_shape_reference(&self) -> Option<&SynthesizedShapeReference> {
        match self {
            Type::SynthesizedShapeReference(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_enum(&self) -> bool {
        match self {
            Type::Enum => true,
            _ => false,
        }
    }

    pub fn is_enum_reference(&self) -> bool {
        self.as_enum_reference().is_some()
    }

    pub fn as_enum_reference(&self) -> Option<&Reference> {
        match self {
            Type::EnumReference(a) => Some(a),
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

    pub fn is_synthesized_enum_variant_reference(&self) -> bool {
        self.as_synthesized_enum_reference().is_some()
    }

    pub fn as_synthesized_enum_variant_reference(&self) -> Option<&SynthesizedEnumReference> {
        match self {
            Type::SynthesizedEnumVariantReference(a) => Some(a),
            _ => None,
        }
    }

    pub fn is_model(&self) -> bool {
        match self {
            Type::Model => true,
            _ => false,
        }
    }

    pub fn is_model_reference(&self) -> bool {
        self.as_model_reference().is_some()
    }

    pub fn as_model_reference(&self) -> Option<&Reference> {
        match self {
            Type::ModelReference(r) => Some(r),
            _ => None,
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

    pub fn is_interface_reference(&self) -> bool {
        self.as_interface_reference().is_some()
    }

    pub fn as_interface_reference(&self) -> Option<(&Reference, &Vec<Type>)> {
        match self {
            Type::InterfaceReference(r, g) => Some((r, g)),
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

    pub fn is_struct_reference(&self) -> bool {
        self.as_struct_reference().is_some()
    }

    pub fn as_struct_reference(&self) -> Option<(&Reference, &Vec<Type>)> {
        match self {
            Type::StructReference(r, g) => Some((r, g)),
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

    pub fn is_struct_static_function_reference(&self) -> bool {
        self.as_struct_static_function_reference().is_some()
    }

    pub fn as_struct_static_function_reference(&self) -> Option<(&Reference, &Vec<Type>)> {
        match self {
            Type::StructStaticFunctionReference(r, g) => Some((r, g)),
            _ => None,
        }
    }

    pub fn is_struct_instance_function_reference(&self) -> bool {
        self.as_struct_instance_function_reference().is_some()
    }

    pub fn as_struct_instance_function_reference(&self) -> Option<(&Reference, &Vec<Type>)> {
        match self {
            Type::StructInstanceFunctionReference(r, g) => Some((r, g)),
            _ => None,
        }
    }

    pub fn is_function_reference(&self) -> bool {
        self.as_function_reference().is_some()
    }

    pub fn as_function_reference(&self) -> Option<&Reference> {
        match self {
            Type::FunctionReference(r) => Some(r),
            _ => None,
        }
    }

    pub fn is_middleware(&self) -> bool {
        match self {
            Type::Middleware => true,
            _ => false,
        }
    }

    pub fn is_middleware_reference(&self) -> bool {
        self.as_middleware_reference().is_some()
    }

    pub fn as_middleware_reference(&self) -> Option<&Reference> {
        match self {
            Type::MiddlewareReference(r) => Some(r),
            _ => None,
        }
    }

    pub fn is_data_set(&self) -> bool {
        match self {
            Type::DataSet => true,
            _ => false,
        }
    }

    pub fn is_data_set_reference(&self) -> bool {
        self.as_data_set_reference().is_some()
    }

    pub fn as_data_set_reference(&self) -> Option<&Reference> {
        match self {
            Type::DataSetReference(r) => Some(r),
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

    pub fn is_namespace(&self) -> bool {
        match self {
            Type::Namespace => true,
            _ => false,
        }
    }

    pub fn is_namespace_reference(&self) -> bool {
        self.as_namespace_reference().is_some()
    }

    pub fn as_namespace_reference(&self) -> Option<&Reference> {
        match self {
            Type::NamespaceReference(r) => Some(r),
            _ => None,
        }
    }

    pub fn is_pipeline(&self) -> bool {
        self.as_pipeline().is_some()
    }

    pub fn as_pipeline(&self) -> Option<(&Type, &Type)> {
        match self {
            Type::Pipeline((a, b)) => Some((a.as_ref(), b.as_ref())),
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
            Type::SynthesizedShapeReference(s) => s.contains_generics(),
            Type::InterfaceReference(_, types) => types.iter().any(|t| t.contains_generics()),
            Type::InterfaceObject(_, types) => types.iter().any(|t| t.contains_generics()),
            Type::StructReference(_, types) => types.iter().any(|t| t.contains_generics()),
            Type::StructObject(_, types) => types.iter().any(|t| t.contains_generics()),
            Type::StructStaticFunctionReference(_, types) => types.iter().any(|t| t.contains_generics()),
            Type::StructInstanceFunctionReference(_, types) => types.iter().any(|t| t.contains_generics()),
            Type::DataSetGroup(inner) => inner.contains_generics(),
            Type::DataSetRecord(a, b) => a.contains_generics() || b.contains_generics(),
            Type::Pipeline((a, b)) => a.contains_generics() || b.contains_generics(),
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
            Type::SynthesizedShapeReference(s) => s.contains_keywords(),
            Type::InterfaceReference(_, types) => types.iter().any(|t| t.contains_keywords()),
            Type::InterfaceObject(_, types) => types.iter().any(|t| t.contains_keywords()),
            Type::StructReference(_, types) => types.iter().any(|t| t.contains_keywords()),
            Type::StructObject(_, types) => types.iter().any(|t| t.contains_keywords()),
            Type::StructStaticFunctionReference(_, types) => types.iter().any(|t| t.contains_keywords()),
            Type::StructInstanceFunctionReference(_, types) => types.iter().any(|t| t.contains_keywords()),
            Type::DataSetGroup(inner) => inner.contains_keywords(),
            Type::DataSetRecord(a, b) => a.contains_keywords() || b.contains_keywords(),
            Type::Pipeline((a, b)) => a.contains_keywords() || b.contains_keywords(),
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
            Type::SynthesizedShape(shape) => Type::SynthesizedShape(shape.replace_generics(map)),
            Type::SynthesizedShapeReference(s) => Type::SynthesizedShapeReference(s.replace_generics(map)),
            Type::InterfaceReference(r, types) => Type::InterfaceReference(r.clone(), types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::InterfaceObject(r, types) => Type::InterfaceObject(r.clone(), types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::StructReference(r, types) => Type::StructReference(r.clone(), types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::StructObject(r, types) => Type::StructObject(r.clone(), types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::StructStaticFunctionReference(r, types) => Type::StructStaticFunctionReference(r.clone(), types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::StructInstanceFunctionReference(r, types) => Type::StructInstanceFunctionReference(r.clone(), types.iter().map(|t| t.replace_generics(map)).collect()),
            Type::DataSetGroup(inner) => Type::DataSetGroup(Box::new(inner.replace_generics(map))),
            Type::DataSetRecord(a, b) => Type::DataSetRecord(
                Box::new(a.replace_generics(map)),
                Box::new(b.replace_generics(map)),
            ),
            Type::Pipeline((a, b)) => Type::Pipeline((
                Box::new(a.replace_generics(map)),
                Box::new(b.replace_generics(map)),
            )),
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
            Type::SynthesizedShape(shape) => Type::SynthesizedShape(shape.replace_keywords(map)),
            Type::SynthesizedShapeReference(s) => Type::SynthesizedShapeReference(s.replace_keywords(map)),
            Type::InterfaceReference(r, types) => Type::InterfaceReference(r.clone(), types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::InterfaceObject(r, types) => Type::InterfaceObject(r.clone(), types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::StructReference(r, types) => Type::StructReference(r.clone(), types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::StructObject(r, types) => Type::StructObject(r.clone(), types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::StructStaticFunctionReference(r, types) => Type::StructStaticFunctionReference(r.clone(), types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::StructInstanceFunctionReference(r, types) => Type::StructInstanceFunctionReference(r.clone(), types.iter().map(|t| t.replace_keywords(map)).collect()),
            Type::DataSetGroup(inner) => Type::DataSetGroup(Box::new(inner.replace_keywords(map))),
            Type::DataSetRecord(a, b) => Type::DataSetRecord(
                Box::new(a.replace_keywords(map)),
                Box::new(b.replace_keywords(map)),
            ),
            Type::Pipeline((a, b)) => Type::Pipeline((
                Box::new(a.replace_keywords(map)),
                Box::new(b.replace_keywords(map)),
            )),
            _ => self.clone(),
        }
    }

    pub fn test(&self, passed: &Type) -> bool {
        match self {
            Type::Undetermined => false,
            Type::Ignored => true,
            Type::Any => true,
            Type::Null => passed.is_null(),
            Type::Bool => passed.is_bool(),
            Type::Int => passed.is_int(),
            Type::Int64 => passed.is_int64(),
            Type::Float32 => passed.is_float32(),
            Type::Float => passed.is_float(),
            Type::Decimal => passed.is_decimal(),
            Type::String => passed.is_string(),
            Type::ObjectId => passed.is_object_id(),
            Type::Date => passed.is_date(),
            Type::DateTime => passed.is_datetime(),
            Type::File => passed.is_file(),
            Type::Regex => passed.is_regex(),
            Type::Model => passed.is_model(),
            Type::DataSet => passed.is_data_set(),
            Type::Enumerable(inner) => passed.is_enumerable() && inner.as_ref().test(passed.as_enumerable().unwrap()),
            Type::Array(inner) => passed.is_array() && inner.as_ref().test(passed.as_array().unwrap()),
            Type::Dictionary(inner) => passed.is_dictionary() && inner.as_ref().test(passed.as_dictionary().unwrap()),
            Type::Tuple(types) => passed.is_tuple() && passed.as_tuple().unwrap().len() == types.len() && types.iter().enumerate().all(|(index, t)| t.test(passed.as_tuple().unwrap().get(index).unwrap())),
            Type::Range(inner) => passed.is_range() && inner.as_ref().test(passed.as_range().unwrap()),
            Type::Union(u) => u.iter().any(|t| t.test(passed)),
            Type::EnumVariant(path, _) => passed.is_enum_variant() && passed.as_enum_variant().unwrap().0 == path,
            Type::InterfaceObject(path, generics, _) => passed.is_interface_object() && path == passed.as_interface_object().unwrap().0 && passed.as_interface_object().unwrap().1.len() == generics.len() && generics.iter().enumerate().all(|(index, t)| t.test(passed.as_interface_object().unwrap().1.get(index).unwrap())),
            Type::ModelObject(path, _) => passed.is_model_object() && passed.as_model_object().unwrap().0 == path,
            Type::DataSetObject(path, _) => passed.is_data_set_object() && passed.as_data_set_object().unwrap().0 == path,
            Type::StructObject(path, _) => passed.is_struct_object() && passed.as_struct_object().unwrap().0 == path,
            Type::DataSetRecord(a, b) => passed.is_data_set_record() && passed.as_data_set_record().unwrap().0.test(a) && passed.as_data_set_record().unwrap().1.test(b),
            Type::FieldType(path, field) => passed.is_field_type() && path.test(passed.as_field_type().unwrap().0) && field.test(passed.as_field_type().unwrap().1),
            Type::FieldReference(s) => passed.is_field_reference() && s == passed.as_field_reference().unwrap(),
            Type::GenericItem(identifier) => true,
            Type::Keyword(k) => passed.is_keyword() && k == passed.as_keyword().unwrap(),
            Type::Optional(inner) => passed.is_null() || inner.test(passed) || (passed.is_optional() && inner.test(passed.as_optional().unwrap())),
            Type::Pipeline((a, b)) => passed.is_pipeline() && a.test(passed.as_pipeline().unwrap().0) && b.test(passed.as_pipeline().unwrap().1),
            Type::SynthesizedShapeReference(r) => false,
            Type::SynthesizedShape(s) => passed.is_synthesized_shape() && s == passed.as_synthesized_shape().unwrap(),
            Type::Namespace => passed.is_namespace(),
            Type::Enum(p, _) => passed.is_enum() && passed.as_enum().unwrap().0 == p,
            Type::SynthesizedEnumVariant(s) => passed.is_synthesized_enum_variant() && s == passed.as_synthesized_enum_variant().unwrap(),
            Type::Struct(p, _) => passed.is_struct() && passed.as_struct().unwrap().0 == p,
            Type::FunctionReference => false,
            Type::Middleware => passed.is_middleware(),
            Type::DataSetGroup(_) => false,
            Type::Interface => passed.is_interface(),
            Type::SynthesizedEnum(_) => false,
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

    pub fn satisfies(&self, constraint: &Type) -> bool {
        if self.is_model_object() && constraint.is_model() {
            return true
        }
        constraint.test(self)
    }

    pub fn replace_field_type<F>(&self, f: F) -> Type where F: Fn(&Type, &Type) -> Type {
        let f_ref = |t: &Type, f: &dyn Fn(&Type, &Type) -> Type| { t.replace_field_type(f) };
        match self {
            Type::Undetermined => self.clone(),
            Type::Ignored => self.clone(),
            Type::Any => self.clone(),
            Type::Null => self.clone(),
            Type::Bool => self.clone(),
            Type::Int => self.clone(),
            Type::Int64 => self.clone(),
            Type::Float32 => self.clone(),
            Type::Float => self.clone(),
            Type::Decimal => self.clone(),
            Type::String => self.clone(),
            Type::ObjectId => self.clone(),
            Type::Date => self.clone(),
            Type::DateTime => self.clone(),
            Type::File => self.clone(),
            Type::Regex => self.clone(),
            Type::Model => self.clone(),
            Type::DataSet => self.clone(),
            Type::Enumerable(t) => Type::Enumerable(Box::new(f_ref(t, &f))),
            Type::Array(t) => Type::Array(Box::new(f_ref(t, &f))),
            Type::Dictionary(t) => Type::Dictionary(Box::new(f_ref(t, &f))),
            Type::Tuple(types) => Type::Tuple(types.iter().map(|t| f_ref(t, &f)).collect()),
            Type::Range(t) => Type::Range(Box::new(f_ref(t, &f))),
            Type::Union(types) => Type::Union(types.iter().map(|t| f_ref(t, &f)).collect()),
            Type::EnumVariant(_, _) => self.clone(),
            Type::InterfaceObject(_, _, _) => self.clone(),
            Type::ModelObject(_, _) => self.clone(),
            Type::StructObject(_, _) => self.clone(),
            Type::DataSetObject(_, _) => self.clone(),
            Type::DataSetRecord(_, _) => self.clone(),
            Type::FieldType(a, b) => f(a.as_ref(), b.as_ref()),
            Type::FieldReference(_) => self.clone(),
            Type::GenericItem(_) => self.clone(),
            Type::Keyword(_) => self.clone(),
            Type::Optional(t) => Type::Optional(Box::new(f_ref(t, &f))),
            Type::Pipeline((t1, t2)) => Type::Pipeline((Box::new(f_ref(t1, &f)), Box::new(f_ref(t2, &f)))),
            _ => self.clone(),
        }
    }
}

impl Display for Type {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Type::Undetermined => f.write_str("Undetermined"),
            Type::Ignored => f.write_str("Ignored"),
            Type::Any => f.write_str("Any"),
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
            Type::Model => f.write_str("Model"),
            Type::DataSet => f.write_str("DataSet"),
            Type::Enumerable(inner) => f.write_str(&format!("Range<{}>", inner)),
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
            Type::Union(types) => f.write_str(&types.iter().map(|t| format!("{t}")).join(" | ")),
            Type::EnumVariant(_, name) => f.write_str(&name.join(".")),
            Type::InterfaceObject(_, _, name) => f.write_str(&name.join(".")),
            Type::ModelObject(_, name) => f.write_str(&name.join(".")),
            Type::StructObject(_, name) => f.write_str(&name.join(".")),
            Type::DataSetObject(_, name) => f.write_str(&name.join(".")),
            Type::DataSetRecord(a, b) => f.write_str(&format!("DataSetRecord<{}, {}>", a, b)),
            Type::FieldType(a, b) => if a.is_union() {
                f.write_str(&format!("({})[{}]", a, b))
            } else {
                f.write_str(&format!("{}[{}]", a, b))
            },
            Type::FieldReference(name) => f.write_str(&format!(".{}", name)),
            Type::GenericItem(name) => f.write_str(name),
            Type::Keyword(k) => Display::fmt(k, f),
            Type::Optional(inner) => if inner.is_union() {
                f.write_str(&format!("({})?", inner))
            } else {
                f.write_str(&format!("{}?", inner))
            },
            Type::Pipeline((i, o)) => f.write_str(&format!("Pipeline<{}, {}>", i, o)),
            Type::SynthesizedShapeReference(r) => Display::fmt(r, f),
            Type::SynthesizedEnumVariant(e) => Display::fmt(e, f),
            Type::SynthesizedShape(shape) => Display::fmt(shape, f),
            Type::Namespace => f.write_str("Namespace"),
            Type::Enum(_, name) => f.write_str(&name.join(".")),
            Type::Struct(_, name) => f.write_str(&name.join(".")),
            Type::FunctionReference => f.write_str("Function"),
            Type::Middleware => f.write_str("Middleware"),
            Type::DataSetGroup(d) => f.write_str(&format!("DataSetGroup<{}>", d)),
            Type::Interface => f.write_str("Interface"),
            Type::SynthesizedEnum(_) => {}
        }
    }
}
