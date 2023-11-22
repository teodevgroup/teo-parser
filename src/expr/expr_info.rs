use teo_teon::Value;
use crate::expr::ReferenceInfo;
use crate::r#type::reference::Reference;
use crate::r#type::Type;

#[derive(Debug, Clone)]
pub struct ExprInfo {
    pub r#type: Type,
    pub value: Option<Value>,
    pub reference_info: Option<ReferenceInfo>,
}

impl ExprInfo {
    pub fn new(r#type: Type, value: Option<Value>, reference_info: Option<ReferenceInfo>) -> Self {
        Self { r#type, value, reference_info }
    }

    pub fn r#type(&self) -> &Type {
        &self.r#type
    }

    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    pub fn reference_info(&self) -> Option<&ReferenceInfo> {
        self.reference_info.as_ref()
    }

    pub fn is_undetermined(&self) -> bool {
        self.r#type().is_undetermined()
    }

    pub fn is_undetermined_anyway(&self) -> bool {
        self.r#type().is_undetermined() && self.reference_info().is_none()
    }

    pub fn undetermined() -> Self {
        ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference_info: None,
        }
    }

    pub fn type_altered(&self, new_type: Type) -> Self {
        ExprInfo {
            r#type: new_type,
            value: self.value.clone(),
            reference_info: self.reference_info.clone(),
        }
    }

    pub fn reference_only(reference_info: ReferenceInfo) -> Self {
        Self::new(Type::Undetermined, None, Some(reference_info))
    }

    pub fn type_only(t: Type) -> Self {
        Self::new(t, None, None)
    }
}
