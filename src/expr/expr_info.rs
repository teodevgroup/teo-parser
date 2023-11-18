use teo_teon::Value;
use crate::r#type::reference::Reference;
use crate::r#type::Type;

#[derive(Debug, Clone)]
pub struct ExprInfo {
    pub r#type: Type,
    pub value: Option<Value>,
    pub reference: Option<Reference>,
    pub generics: Option<Vec<Type>>,
}

impl ExprInfo {
    pub fn new(r#type: Type, value: Option<Value>, reference: Option<Reference>, generics: Option<Vec<Type>>) -> Self {
        Self { r#type, value, reference, generics, }
    }

    pub fn r#type(&self) -> &Type {
        &self.r#type
    }

    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    pub fn reference(&self) -> Option<&Reference> {
        self.reference.as_ref()
    }

    pub fn generics(&self) -> Option<&Vec<Type>> {
        self.generics.as_ref()
    }

    pub fn is_undetermined(&self) -> bool {
        self.r#type().is_undetermined()
    }

    pub fn undetermined() -> Self {
        ExprInfo {
            r#type: Type::Undetermined,
            value: None,
            reference: None,
            generics: None,
        }
    }

    pub fn type_altered(&self, new_type: Type) -> Self {
        ExprInfo {
            r#type: new_type,
            value: self.value.clone(),
            reference: self.reference.clone(),
            generics: self.generics.clone(),
        }
    }

    pub fn type_only(t: Type) -> Self {
        ExprInfo {
            r#type: t,
            value: None,
            reference: None,
            generics: None,
        }
    }

    pub fn as_path(&self) -> Option<&Vec<usize>> {
        self.reference().map(|r| r.path())
    }
}
