use std::collections::BTreeMap;
use crate::r#type::keyword::Keyword;

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub(crate) enum Type {
    Undetermined,
    Ignored,
    Any,
    Null,
    Bool,
    Int,
    Int64,
    Float32,
    Float,
    Decimal,
    String,
    ObjectId,
    Date,
    DateTime,
    File,
    Regex,
    Model,
    Array(Box<Type>),
    Dictionary(Box<Type>),
    Tuple(Vec<Type>),
    Range(Box<Type>),
    Union(Vec<Type>),
    EnumVariant(Vec<usize>),
    InterfaceObject(Vec<usize>, Vec<Type>),
    ModelObject(Vec<usize>),
    StructObject(Vec<usize>),
    ModelScalarFields(Vec<usize>),
    ModelScalarFieldsWithoutVirtuals(Vec<usize>),
    ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(Vec<usize>),
    FieldType(Vec<usize>, String),
    GenericItem(String),
    Keyword(Keyword),
    Optional(Box<Type>),
}

impl Type {

    pub(crate) fn is_undetermined(&self) -> bool {
        match self {
            Type::Undetermined => true,
            _ => false,
        }
    }

    pub(crate) fn is_ignored(&self) -> bool {
        match self {
            Type::Ignored => true,
            _ => false,
        }
    }

    pub(crate) fn is_any(&self) -> bool {
        match self {
            Type::Any => true,
            _ => false,
        }
    }

    pub(crate) fn is_null(&self) -> bool {
        match self {
            Type::Null => true,
            _ => false,
        }
    }

    pub(crate) fn is_bool(&self) -> bool {
        match self {
            Type::Bool => true,
            _ => false,
        }
    }

    pub(crate) fn is_int(&self) -> bool {
        match self {
            Type::Int => true,
            _ => false,
        }
    }

    pub(crate) fn is_int64(&self) -> bool {
        match self {
            Type::Int64 => true,
            _ => false,
        }
    }

    pub(crate) fn is_float32(&self) -> bool {
        match self {
            Type::Float32 => true,
            _ => false,
        }
    }

    pub(crate) fn is_float(&self) -> bool {
        match self {
            Type::Float => true,
            _ => false,
        }
    }

    pub(crate) fn is_decimal(&self) -> bool {
        match self {
            Type::Decimal => true,
            _ => false,
        }
    }

    pub(crate) fn is_string(&self) -> bool {
        match self {
            Type::String => true,
            _ => false,
        }
    }

    pub(crate) fn is_object_id(&self) -> bool {
        match self {
            Type::ObjectId => true,
            _ => false,
        }
    }

    pub(crate) fn is_date(&self) -> bool {
        match self {
            Type::Date => true,
            _ => false,
        }
    }

    pub(crate) fn is_datetime(&self) -> bool {
        match self {
            Type::DateTime => true,
            _ => false,
        }
    }

    pub(crate) fn is_file(&self) -> bool {
        match self {
            Type::File => true,
            _ => false,
        }
    }

    pub(crate) fn is_regex(&self) -> bool {
        match self {
            Type::Regex => true,
            _ => false,
        }
    }

    pub(crate) fn is_model(&self) -> bool {
        match self {
            Type::Model => true,
            _ => false,
        }
    }

    pub(crate) fn is_array(&self) -> bool {
        self.as_array().is_some()
    }

    pub(crate) fn as_array(&self) -> Option<&Type> {
        match self {
            Self::Array(inner) => Some(inner.as_ref()),
            _ => None,
        }
    }

    pub(crate) fn is_dictionary(&self) -> bool {
        self.as_dictionary().is_some()
    }

    pub(crate) fn as_dictionary(&self) -> Option<&Type> {
        match self {
            Self::Dictionary(v) => Some(v.as_ref()),
            _ => None,
        }
    }

    pub(crate) fn is_tuple(&self) -> bool {
        self.as_tuple().is_some()
    }

    pub(crate) fn as_tuple(&self) -> Option<&Vec<Type>> {
        match self {
            Self::Tuple(types) => Some(types),
            _ => None,
        }
    }

    pub(crate) fn is_range(&self) -> bool {
        self.as_range().is_some()
    }

    pub(crate) fn as_range(&self) -> Option<&Type> {
        match self {
            Self::Range(t) => Some(t.as_ref()),
            _ => None,
        }
    }

    pub(crate) fn is_union(&self) -> bool {
        self.as_union().is_some()
    }

    pub(crate) fn as_union(&self) -> Option<&Vec<Type>> {
        match self {
            Self::Union(types) => Some(types),
            _ => None,
        }
    }

    pub(crate) fn is_enum_variant(&self) -> bool {
        self.as_enum_variant().is_some()
    }

    pub(crate) fn as_enum_variant(&self) -> Option<&Vec<usize>> {
        match self {
            Self::EnumVariant(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_interface_object(&self) -> bool {
        self.as_interface_object().is_some()
    }

    pub(crate) fn as_interface_object(&self) -> Option<(&Vec<usize>, &Vec<Type>)> {
        match self {
            Self::InterfaceObject(path, types) => Some((path, types)),
            _ => None,
        }
    }

    pub(crate) fn is_model_object(&self) -> bool {
        self.as_model_object().is_some()
    }

    pub(crate) fn as_model_object(&self) -> Option<&Vec<usize>> {
        match self {
            Self::ModelObject(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_struct_object(&self) -> bool {
        self.as_struct_object().is_some()
    }

    pub(crate) fn as_struct_object(&self) -> Option<&Vec<usize>> {
        match self {
            Self::StructObject(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_model_scalar_fields(&self) -> bool {
        self.as_model_scalar_fields().is_some()
    }

    pub(crate) fn as_model_scalar_fields(&self) -> Option<&Vec<usize>> {
        match self {
            Self::ModelScalarFields(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_model_scalar_fields_without_virtuals(&self) -> bool {
        self.as_model_scalar_fields_without_virtuals().is_some()
    }

    pub(crate) fn as_model_scalar_fields_without_virtuals(&self) -> Option<&Vec<usize>> {
        match self {
            Self::ModelScalarFieldsWithoutVirtuals(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_model_scalar_fields_and_cached_properties_without_virtuals(&self) -> bool {
        self.as_model_scalar_fields_and_cached_properties_without_virtuals().is_some()
    }

    pub(crate) fn as_model_scalar_fields_and_cached_properties_without_virtuals(&self) -> Option<&Vec<usize>> {
        match self {
            Self::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_field_type(&self) -> bool {
        self.as_field_type().is_some()
    }

    pub(crate) fn as_field_type(&self) -> Option<(&Vec<usize>, &str)> {
        match self {
            Self::FieldType(path, field) => Some((path, field)),
            _ => None,
        }
    }

    pub(crate) fn is_generic_item(&self) -> bool {
        self.as_generic_item().is_some()
    }

    pub(crate) fn as_generic_item(&self) -> Option<&str> {
        match self {
            Self::GenericItem(name) => Some(name),
            _ => None,
        }
    }

    pub(crate) fn is_keyword(&self) -> bool {
        self.as_keyword().is_some()
    }

    pub(crate) fn as_keyword(&self) -> Option<&Keyword> {
        match self {
            Self::Keyword(kw) => Some(kw),
            _ => None,
        }
    }

    pub(crate) fn is_optional(&self) -> bool {
        self.as_optional().is_some()
    }

    pub(crate) fn as_optional(&self) -> Option<&Type> {
        match self {
            Type::Optional(t) => Some(t),
            _ => None,
        }
    }

    pub(crate) fn is_int_32_or_64(&self) -> bool {
        match self {
            Type::Int | Type::Int64 => true,
            _ => false,
        }
    }

    pub(crate) fn is_float_32_or_64(&self) -> bool {
        match self {
            Type::Float32 | Type::Float => true,
            _ => false,
        }
    }

    pub(crate) fn is_container(&self) -> bool {
        match self {
            Type::Undetermined => false,
            Type::Ignored => false,
            Type::Any => false,
            Type::Null => false,
            Type::Bool => false,
            Type::Int => false,
            Type::Int64 => false,
            Type::Float32 => false,
            Type::Float => false,
            Type::Decimal => false,
            Type::String => false,
            Type::ObjectId => false,
            Type::Date => false,
            Type::DateTime => false,
            Type::File => false,
            Type::Regex => false,
            Type::Model => false,
            Type::Array(_) => true,
            Type::Dictionary(_) => true,
            Type::Tuple(_) => true,
            Type::Range(_) => true,
            Type::Union(_) => true,
            Type::EnumVariant(_) => false,
            Type::InterfaceObject(_, _) => true,
            Type::ModelObject(_) => false,
            Type::StructObject(_) => false,
            Type::ModelScalarFields(_) => false,
            Type::ModelScalarFieldsWithoutVirtuals(_) => false,
            Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(_) => false,
            Type::FieldType(_, _) => false,
            Type::GenericItem(_) => false,
            Type::Keyword(_) => false,
            Type::Optional(_) => true,
        }
    }

    pub(crate) fn replace_generics(&self, map: &BTreeMap<String, &Type>) -> Self {
        if let Some(name) = self.as_generic_item() {
            if let Some(t) = map.get(name) {
                (*t).clone()
            } else {
                self.clone()
            }
        } else if self.is_container() {
            match self {
                Type::Array(inner) => Type::Array(Box::new(inner.replace_generics(map))),
                Type::Dictionary(v) => Type::Dictionary(Box::new(v.replace_generics(map))),
                Type::Tuple(inner) => Type::Tuple(inner.iter().map(|t| t.replace_generics(map)).collect()),
                Type::Range(inner) => Type::Range(Box::new(inner.replace_generics(map))),
                Type::Union(inner) => Type::Union(inner.iter().map(|t| t.replace_generics(map)).collect()),
                Type::InterfaceObject(path, generics) => Type::InterfaceObject(path.clone(), generics.iter().map(|t| t.replace_generics(map)).collect()),
                Type::Optional(inner) => Type::Optional(Box::new(inner.replace_generics(map))),
                _ => unreachable!(),
            }
        } else {
            self.clone()
        }
    }

    pub(crate) fn replace_keywords(&self, map: &BTreeMap<Keyword, &Type>) -> Self {
        if let Some(name) = self.as_keyword() {
            if let Some(t) = map.get(name) {
                (*t).clone()
            } else {
                self.clone()
            }
        } else if self.is_container() {
            match self {
                Type::Array(inner) => Type::Array(Box::new(inner.replace_keywords(map))),
                Type::Dictionary(v) => Type::Dictionary(Box::new(v.replace_keywords(map))),
                Type::Tuple(inner) => Type::Tuple(inner.iter().map(|t| t.replace_keywords(map)).collect()),
                Type::Range(inner) => Type::Range(Box::new(inner.replace_keywords(map))),
                Type::Union(inner) => Type::Union(inner.iter().map(|t| t.replace_keywords(map)).collect()),
                Type::InterfaceObject(path, generics) => Type::InterfaceObject(path.clone(), generics.iter().map(|t| t.replace_keywords(map)).collect()),
                Type::Optional(inner) => Type::Optional(Box::new(inner.replace_keywords(map))),
                _ => unreachable!(),
            }
        } else {
            self.clone()
        }
    }
}
