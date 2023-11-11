use teo_teon::Value;
use crate::r#type::Type;

#[derive(Debug, Clone)]
pub struct TypeAndValue {
    pub r#type: Type,
    pub value: Option<Value>,
}

impl TypeAndValue {
    pub fn new(r#type: Type, value: Option<Value>) -> Self {
        Self { r#type, value }
    }

    pub fn r#type(&self) -> &Type {
        &self.r#type
    }

    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    pub fn is_undetermined(&self) -> bool {
        self.r#type().is_undetermined()
    }

    pub fn undetermined() -> Self {
        TypeAndValue {
            r#type: Type::Undetermined,
            value: None,
        }
    }

    pub fn with_type(&self, new_type: Type) -> Self {
        TypeAndValue {
            r#type: new_type,
            value: self.value.clone()
        }
    }

    pub fn with_value(&self, new_value: Option<Value>) -> Self {
        TypeAndValue {
            r#type: self.r#type.clone(),
            value: new_value,
        }
    }

    pub fn type_only(t: Type) -> Self {
        TypeAndValue {
            r#type: t,
            value: None
        }
    }

    pub fn as_path(&self) -> Option<&Vec<usize>> {
        match self.r#type() {
            Type::EnumReference(r) => Some(r.path()),
            Type::ConfigReference(r) => Some(r.path()),
            Type::ModelReference(r) => Some(r.path()),
            Type::ModelFieldReference(r) => Some(r.path()),
            Type::InterfaceReference(r, _) => Some(r.path()),
            Type::InterfaceFieldReference(r, _) => Some(r.path()),
            Type::StructReference(r, _) => Some(r.path()),
            Type::StructStaticFunctionReference(r, _) => Some(r.path()),
            Type::StructInstanceFunctionReference(r, _) => Some(r.path()),
            Type::FunctionReference(r) => Some(r.path()),
            Type::MiddlewareReference(r) => Some(r.path()),
            Type::DataSetReference(r) => None,
            Type::NamespaceReference(r) => None,
            Type::DecoratorReference(r) => Some(r.path()),
            Type::PipelineItemReference(r) => Some(r.path()),
            _ => None,
        }
    }
}