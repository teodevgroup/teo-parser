use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use itertools::Itertools;
use crate::r#type::keyword::Keyword;

#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Type {
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
    EnumVariant(Vec<usize>, Vec<String>),
    InterfaceObject(Vec<usize>, Vec<Type>, Vec<String>),
    ModelObject(Vec<usize>, Vec<String>),
    StructObject(Vec<usize>, Vec<String>),
    ModelScalarFields(Box<Type>),
    ModelScalarFieldsWithoutVirtuals(Box<Type>),
    ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(Box<Type>),
    ModelRelations(Box<Type>),
    ModelDirectRelations(Box<Type>),
    FieldType(Box<Type>, Box<Type>),
    FieldReference(String),
    GenericItem(String),
    Keyword(Keyword),
    Optional(Box<Type>),
    Pipeline((Box<Type>, Box<Type>)),
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

    pub(crate) fn as_enum_variant(&self) -> Option<(&Vec<usize>, &Vec<String>)> {
        match self {
            Self::EnumVariant(path, name) => Some((path, name)),
            _ => None,
        }
    }

    pub(crate) fn is_interface_object(&self) -> bool {
        self.as_interface_object().is_some()
    }

    pub(crate) fn as_interface_object(&self) -> Option<(&Vec<usize>, &Vec<Type>, &Vec<String>)> {
        match self {
            Self::InterfaceObject(path, types, name) => Some((path, types, name)),
            _ => None,
        }
    }

    pub(crate) fn is_model_object(&self) -> bool {
        self.as_model_object().is_some()
    }

    pub(crate) fn as_model_object(&self) -> Option<(&Vec<usize>, &Vec<String>)> {
        match self {
            Self::ModelObject(path, name) => Some((path, name)),
            _ => None,
        }
    }

    pub(crate) fn is_struct_object(&self) -> bool {
        self.as_struct_object().is_some()
    }

    pub(crate) fn as_struct_object(&self) -> Option<(&Vec<usize>, &Vec<String>)> {
        match self {
            Self::StructObject(path, name) => Some((path, name)),
            _ => None,
        }
    }

    pub(crate) fn is_model_scalar_fields(&self) -> bool {
        self.as_model_scalar_fields().is_some()
    }

    pub(crate) fn as_model_scalar_fields(&self) -> Option<&Type> {
        match self {
            Self::ModelScalarFields(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_model_scalar_fields_without_virtuals(&self) -> bool {
        self.as_model_scalar_fields_without_virtuals().is_some()
    }

    pub(crate) fn as_model_scalar_fields_without_virtuals(&self) -> Option<&Type> {
        match self {
            Self::ModelScalarFieldsWithoutVirtuals(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_model_scalar_fields_and_cached_properties_without_virtuals(&self) -> bool {
        self.as_model_scalar_fields_and_cached_properties_without_virtuals().is_some()
    }

    pub(crate) fn as_model_scalar_fields_and_cached_properties_without_virtuals(&self) -> Option<&Type> {
        match self {
            Self::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_model_relations(&self) -> bool {
        self.as_model_scalar_fields().is_some()
    }

    pub(crate) fn as_model_relations(&self) -> Option<&Type> {
        match self {
            Self::ModelRelations(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_model_direct_relations(&self) -> bool {
        self.as_model_direct_relations().is_some()
    }

    pub(crate) fn as_model_direct_relations(&self) -> Option<&Type> {
        match self {
            Self::ModelDirectRelations(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn is_field_type(&self) -> bool {
        self.as_field_type().is_some()
    }

    pub(crate) fn as_field_type(&self) -> Option<(&Type, &Type)> {
        match self {
            Self::FieldType(path, field) => Some((path, field)),
            _ => None,
        }
    }

    pub(crate) fn is_field_reference(&self) -> bool {
        self.as_field_reference().is_some()
    }

    pub(crate) fn as_field_reference(&self) -> Option<&str> {
        match self {
            Self::FieldReference(name) => Some(name.as_str()),
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

    pub(crate) fn is_pipeline(&self) -> bool {
        self.as_pipeline().is_some()
    }

    pub(crate) fn as_pipeline(&self) -> Option<(&Type, &Type)> {
        match self {
            Type::Pipeline((a, b)) => Some((a.as_ref(), b.as_ref())),
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

    pub(crate) fn is_any_int_or_float(&self) -> bool {
        self.is_int_32_or_64() || self.is_float_32_or_64()
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
            Type::EnumVariant(_, _) => false,
            Type::InterfaceObject(_, _, _) => true,
            Type::ModelObject(_, _) => false,
            Type::StructObject(_, _) => false,
            Type::ModelScalarFields(_) => false,
            Type::ModelScalarFieldsWithoutVirtuals(_) => false,
            Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(_) => false,
            Type::ModelRelations(_) => false,
            Type::ModelDirectRelations(_) => false,
            Type::FieldType(_, _) => false,
            Type::FieldReference(_) => false,
            Type::GenericItem(_) => false,
            Type::Keyword(_) => false,
            Type::Optional(_) => true,
            Type::Pipeline(_) => false,
        }
    }

    pub(crate) fn contains_generics(&self) -> bool {
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
            Type::Array(inner) => inner.contains_generics(),
            Type::Dictionary(inner) => inner.contains_generics(),
            Type::Tuple(types) => types.iter().any(|t| t.contains_generics()),
            Type::Range(inner) => inner.contains_generics(),
            Type::Union(types) => types.iter().any(|t| t.contains_generics()),
            Type::EnumVariant(_, _) => false,
            Type::InterfaceObject(_, types, _) => types.iter().any(|t| t.contains_generics()),
            Type::ModelObject(_, _) => false,
            Type::StructObject(_, _) => false,
            Type::ModelScalarFields(inner) => inner.contains_generics(),
            Type::ModelScalarFieldsWithoutVirtuals(inner) => inner.contains_generics(),
            Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(inner) => inner.contains_generics(),
            Type::ModelRelations(inner) => inner.contains_generics(),
            Type::ModelDirectRelations(inner) => inner.contains_generics(),
            Type::FieldType(a, b) => a.contains_generics() || b.contains_generics(),
            Type::FieldReference(_) => false,
            Type::GenericItem(_) => true,
            Type::Keyword(_) => false,
            Type::Optional(inner) => inner.contains_generics(),
            Type::Pipeline((a, b)) => a.contains_generics() || b.contains_generics(),
        }
    }

    pub(crate) fn replace_generics(&self, map: &BTreeMap<String, &Type>) -> Self {
        if let Some(name) = self.as_generic_item() {
            if let Some(t) = map.get(name) {
                (*t).clone()
            } else {
                self.clone()
            }
        } else {
            match self {
                Type::Array(inner) => Type::Array(Box::new(inner.replace_generics(map))),
                Type::Dictionary(v) => Type::Dictionary(Box::new(v.replace_generics(map))),
                Type::Tuple(inner) => Type::Tuple(inner.iter().map(|t| t.replace_generics(map)).collect()),
                Type::Range(inner) => Type::Range(Box::new(inner.replace_generics(map))),
                Type::Union(inner) => Type::Union(inner.iter().map(|t| t.replace_generics(map)).collect()),
                Type::InterfaceObject(path, generics, name) => Type::InterfaceObject(path.clone(), generics.iter().map(|t| t.replace_generics(map)).collect(), name.clone()),
                Type::Optional(inner) => Type::Optional(Box::new(inner.replace_generics(map))).flatten(),
                Type::Pipeline((a, b)) => Type::Pipeline((Box::new(a.replace_generics(map)), Box::new(b.replace_generics(map)))),
                _ => self.clone(),
            }
        }
    }

    pub(crate) fn replace_keywords(&self, map: &BTreeMap<Keyword, &Type>) -> Self {
        if let Some(name) = self.as_keyword() {
            if let Some(t) = map.get(name) {
                (*t).clone()
            } else {
                self.clone()
            }
        } else {
            match self {
                Type::Array(inner) => Type::Array(Box::new(inner.replace_keywords(map))),
                Type::Dictionary(v) => Type::Dictionary(Box::new(v.replace_keywords(map))),
                Type::Tuple(inner) => Type::Tuple(inner.iter().map(|t| t.replace_keywords(map)).collect()),
                Type::Range(inner) => Type::Range(Box::new(inner.replace_keywords(map))),
                Type::Union(inner) => Type::Union(inner.iter().map(|t| t.replace_keywords(map)).collect()),
                Type::InterfaceObject(path, generics, name) => Type::InterfaceObject(path.clone(), generics.iter().map(|t| t.replace_keywords(map)).collect(), name.clone()),
                Type::Optional(inner) => Type::Optional(Box::new(inner.replace_keywords(map))).flatten(),
                Type::Pipeline((a, b)) => Type::Pipeline((Box::new(a.replace_keywords(map)), Box::new(b.replace_keywords(map)))),
                Type::ModelScalarFields(inner) => Type::ModelScalarFields(Box::new(inner.replace_keywords(map))),
                Type::ModelScalarFieldsWithoutVirtuals(inner) => Type::ModelScalarFieldsWithoutVirtuals(Box::new(inner.replace_keywords(map))),
                Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(inner) => Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(Box::new(inner.replace_keywords(map))),
                Type::ModelRelations(inner) => Type::ModelRelations(Box::new(inner.replace_keywords(map))),
                Type::ModelDirectRelations(inner) => Type::ModelDirectRelations(Box::new(inner.replace_keywords(map))),
                _ => self.clone(),
            }
        }
    }

    pub(crate) fn test(&self, passed: &Type) -> bool {
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
            Type::Array(inner) => passed.is_array() && inner.as_ref().test(passed.as_array().unwrap()),
            Type::Dictionary(inner) => passed.is_dictionary() && inner.as_ref().test(passed.as_dictionary().unwrap()),
            Type::Tuple(types) => passed.is_tuple() && passed.as_tuple().unwrap().len() == types.len() && types.iter().enumerate().all(|(index, t)| t.test(passed.as_tuple().unwrap().get(index).unwrap())),
            Type::Range(inner) => passed.is_range() && inner.as_ref().test(passed.as_range().unwrap()),
            Type::Union(u) => u.iter().any(|t| t.test(passed)),
            Type::EnumVariant(path, _) => passed.is_enum_variant() && passed.as_enum_variant().unwrap().0 == path,
            Type::InterfaceObject(path, generics, _) => passed.is_interface_object() && path == passed.as_interface_object().unwrap().0 && passed.as_interface_object().unwrap().1.len() == generics.len() && generics.iter().enumerate().all(|(index, t)| t.test(passed.as_interface_object().unwrap().1.get(index).unwrap())),
            Type::ModelObject(path, _) => passed.is_model_object() && passed.as_model_object().unwrap().0 == path,
            Type::StructObject(path, _) => passed.is_struct_object() && passed.as_struct_object().unwrap().0 == path,
            Type::ModelScalarFields(path) => passed.is_model_scalar_fields() && passed.as_model_scalar_fields().unwrap().test(path),
            Type::ModelScalarFieldsWithoutVirtuals(path) => passed.is_model_scalar_fields_without_virtuals() && passed.as_model_scalar_fields_without_virtuals().unwrap().test(path),
            Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(path) => passed.is_model_scalar_fields_and_cached_properties_without_virtuals() && passed.as_model_scalar_fields_and_cached_properties_without_virtuals().unwrap().test(path),
            Type::ModelRelations(path) => passed.is_model_relations() && passed.as_model_relations().unwrap().test(path),
            Type::ModelDirectRelations(path) => passed.is_model_direct_relations() && passed.as_model_direct_relations().unwrap().test(path),
            Type::FieldType(path, field) => passed.is_field_type() && path.test(passed.as_field_type().unwrap().0) && field.test(passed.as_field_type().unwrap().1),
            Type::FieldReference(s) => passed.is_field_reference() && s == passed.as_field_reference().unwrap(),
            Type::GenericItem(identifier) => passed.is_generic_item() && passed.as_generic_item().unwrap() == identifier.as_str(),
            Type::Keyword(k) => passed.is_keyword() && k == passed.as_keyword().unwrap(),
            Type::Optional(inner) => passed.is_null() || inner.test(passed) || (passed.is_optional() && inner.test(passed.as_optional().unwrap())),
            Type::Pipeline((a, b)) => passed.is_pipeline() && a.test(passed.as_pipeline().unwrap().0) && b.test(passed.as_pipeline().unwrap().1),
        }
    }

    pub(crate) fn unwrap_optional(&self) -> &Type {
        if self.is_optional() {
            self.as_optional().unwrap()
        } else {
            self
        }
    }

    pub(crate) fn unwrap_array(&self) -> &Type {
        if self.is_array() {
            self.as_array().unwrap()
        } else {
            self
        }
    }

    pub(crate) fn flatten(&self) -> Type {
        if let Some(inner) = self.as_optional() {
            if inner.is_optional() {
                return inner.flatten();
            }
        }
        self.clone()
    }

    pub(crate) fn satisfies(&self, constraint: &Type) -> bool {
        if self.is_model_object() && constraint.is_model() {
            return true
        }
        constraint.test(self)
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
            Type::ModelScalarFields(inner) => f.write_str(&format!("ModelScalarFields<{}>", inner)),
            Type::ModelScalarFieldsWithoutVirtuals(inner) => f.write_str(&format!("ModelScalarFieldsWithoutVirtuals<{}>", inner)),
            Type::ModelScalarFieldsAndCachedPropertiesWithoutVirtuals(inner) => f.write_str(&format!("ModelScalarFieldsAndCachedPropertiesWithoutVirtuals<{}>", inner)),
            Type::ModelRelations(inner) => f.write_str(&format!("ModelRelations<{}>", inner)),
            Type::ModelDirectRelations(inner) => f.write_str(&format!("ModelDirectRelations<{}>", inner)),
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
        }
    }
}
