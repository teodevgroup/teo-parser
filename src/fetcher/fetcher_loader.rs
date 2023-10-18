use std::collections::BTreeMap;
use std::sync::Arc;
use educe::Educe;
use maplit::btreemap;
use teo_teon::Value;

#[derive(Debug)]
pub struct FetcherLoader where {
    struct_loaders: BTreeMap<Vec<String>, StructLoader>,
}

impl FetcherLoader {

    pub fn new() -> Self {
        Self {
            struct_loaders: btreemap! {}
        }
    }

    pub fn define_struct(&mut self, path: Vec<String>, loader: StructLoader) {
        self.struct_loaders.insert(path, loader);
    }
}

#[derive(Debug)]
pub struct StructLoader {
    functions: BTreeMap<String, Function>,
    static_functions: BTreeMap<String, StaticFunction>,
}

impl StructLoader {

    pub fn new() -> Self {
        Self {
            functions: btreemap! {},
            static_functions: btreemap! {},
        }
    }

    pub fn define_function(&mut self, name: impl Into<String>, function: Function) {
        self.functions.insert(name.into(), function);
    }

    pub fn define_static_function(&mut self, name: impl Into<String>, function: StaticFunction) {
        self.static_functions.insert(name.into(), function);
    }
}

#[derive(Educe)]
#[educe(Debug)]
pub struct Function {
    pub name: String,
    #[educe(Debug(ignore))]
    pub call: Arc<dyn FunctionCall>,
}

#[derive(Educe)]
#[educe(Debug)]
pub struct StaticFunction {
    pub name: String,
    #[educe(Debug(ignore))]
    pub call: Arc<dyn StaticFunctionCall>,
}

pub trait FunctionCall {
    fn call(&self, this: Value, arguments: BTreeMap<String, Value>) -> Result<Option<Value>, String>;
}

impl<F> FunctionCall for F where
    F: Fn(Value, BTreeMap<String, Value>) -> Result<Option<Value>, String> {
    fn call(&self, this: Value, arguments: BTreeMap<String, Value>) -> Result<Option<Value>, String> {
        self(this, arguments)
    }
}

pub trait StaticFunctionCall {
    fn call(&self, arguments: BTreeMap<String, Value>) -> Result<Value, String>;
}

impl<F> StaticFunctionCall for F where
    F: Fn(BTreeMap<String, Value>) -> Result<Value, String> {
    fn call(&self, arguments: BTreeMap<String, Value>) -> Result<Value, String> {
        self(arguments)
    }
}

