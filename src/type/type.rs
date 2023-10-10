use crate::r#type::keyword::TypeKeyword;

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
    RegExp,
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
    Keyword(TypeKeyword),
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

    pub(crate) fn is_regexp(&self) -> bool {
        match self {
            Type::RegExp => true,
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

    pub(crate) fn as_keyword(&self) -> Option<&TypeKeyword> {
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









    pub(crate) fn contains<F>(&self, f: F) -> bool where F: Fn(&Self) -> bool {
        if self.is_container() {
            match self {
                Type::Array(t) => t.as_ref().contains(f),
                Type::Dictionary(v) => {
                    let matcher = |f: &dyn Fn(&Self) -> bool, t: &Type | { f(t) };
                    matcher(&f, v.as_ref())
                },
                Type::Tuple(t) => t.iter().find(|t| f(*t)).is_some(),
                Type::Range(t) => t.as_ref().contains(f),
                Type::Union(u) => u.iter().find(|t| f(*t)).is_some(),
                Type::Optional(o) => o.as_ref().contains(f),
                _ => false,
            }
        } else {
            f(self)
        }
    }

    pub(crate) fn is_container(&self) -> bool {
        match self {
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
            Type::Array(_) => true,
            Type::Dictionary(_) => true,
            Type::Tuple(_) => true,
            Type::Range(_) => true,
            Type::Union(_) => true,
            Type::Ignored => false,
            Type::Enum(_) => false,
            Type::Model(_) => false,
            Type::Interface(_, _) => false,
            Type::ModelScalarField(_) => false,
            Type::ModelScalarFieldAndCachedProperty(_) => false,
            Type::FieldType(_, _) => false,
            Type::GenericItem(_) => false,
            Type::Optional(_) => true,
            Type::Undetermined => false,
            Type::Object(_) => false,
            Type::Keyword(_) => false,
        }
    }

    pub(crate) fn replace_generics(&self, map: &HashMap<String, &Type>) -> Self {
        match self {
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
            Type::Array(inner) => Type::Array(Box::new(inner.replace_generics(map))),
            Type::Dictionary(v) => Type::Dictionary(Box::new(v.replace_generics(map))),
            Type::Tuple(inner) => Type::Tuple(inner.iter().map(|t| t.replace_generics(map)).collect()),
            Type::Range(inner) => Type::Range(Box::new(inner.replace_generics(map))),
            Type::Union(inner) => Type::Union(inner.iter().map(|t| t.replace_generics(map)).collect()),
            Type::Ignored => self.clone(),
            Type::Enum(_) => self.clone(),
            Type::Model(_) => self.clone(),
            Type::Interface(path, generics) => Type::Interface(path.clone(), generics.iter().map(|t| t.replace_generics(map)).collect()),
            Type::ModelScalarField(_) => self.clone(),
            Type::ModelScalarFieldAndCachedProperty(_) => self.clone(),
            Type::FieldType(_, _) => self.clone(),
            Type::GenericItem(name) => map.get(name).cloned().unwrap_or(&Type::Undetermined).clone(),
            Type::Optional(inner) => Type::Optional(Box::new(inner.replace_generics(map))),
            Type::Undetermined => self.clone(),
            Type::Keyword(_) => self.clone(),
            Type::Object(_) => self.clone(),
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

    pub(crate) fn is_enum(&self) -> bool {
        match self {
            Type::Enum(_) => true,
            _ => false,
        }
    }

    /// is standard builtin types
    pub(crate) fn is_builtin(&self) -> bool {
        use Type::*;
        match self {
            Null |
            String |
            ObjectId |
            Date |
            DateTime |
            Bool |
            Int |
            Int64 |
            Float32 |
            Float |
            Decimal |
            File |
            Array(_) |
            Dictionary(_) |
            Tuple(_) => true,
            Optional(inner) => inner.is_builtin(),
            _ => false,
        }
    }

    pub(crate) fn is_interface(&self) -> bool {
        match self {
            Type::Interface(_, __) => true,
            _ => false,
        }
    }

    pub(crate) fn model_path(&self) -> Option<&Vec<usize>> {
        match self {
            Type::Model(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn enum_path(&self) -> Option<&Vec<usize>> {
        match self {
            Type::Enum(path) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn interface_path(&self) -> Option<&Vec<usize>> {
        match self {
            Type::Interface(path, _) => Some(path),
            _ => None,
        }
    }

    pub(crate) fn interface_generics(&self) -> Option<&Vec<Type>> {
        match self {
            Type::Interface(_, generics) => Some(generics),
            _ => None,
        }
    }
}