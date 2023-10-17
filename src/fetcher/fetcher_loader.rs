use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use educe::Educe;
use maplit::btreemap;
use teo_teon::Value;

#[derive(Debug)]
pub struct FetcherLoader<T, E> where T: From<Value>, E: Error {
    struct_loaders: BTreeMap<Vec<String>, StructLoader<T, E>>,
}

impl<T, E> FetcherLoader<T, E> where T: From<Value>, E: Error {

    pub fn new() -> Self {
        Self {
            struct_loaders: btreemap! {}
        }
    }

    pub fn define_struct(&mut self, path: Vec<String>, loader: StructLoader<T, E>) {
        self.struct_loaders.insert(path, loader);
    }
}

#[derive(Debug)]
pub struct StructLoader<T, E> where T: From<Value>, E: Error {
    functions: BTreeMap<String, Function<T, E>>,
    static_functions: BTreeMap<String, StaticFunction<T, E>>,
}

impl<T, E> StructLoader<T, E> where T: From<Value>, E: Error {

    pub fn new() -> Self {
        Self {
            functions: btreemap! {},
            static_functions: btreemap! {},
        }
    }

    pub fn define_function(&mut self, name: impl Into<String>, function: Function<T, E>) {
        self.functions.insert(name.into(), function);
    }

    pub fn define_static_function(&mut self, name: impl Into<String>, function: StaticFunction<T, E>) {
        self.static_functions.insert(name.into(), function);
    }
}

#[derive(Educe)]
#[educe(Debug)]
pub struct Function<T, E> where T: From<Value>, E: Error {
    pub name: String,
    #[educe(Debug(ignore))]
    pub call: Arc<dyn FunctionCall<T, E>>,
}

#[derive(Educe)]
#[educe(Debug)]
pub struct StaticFunction<T, E> where T: From<Value>, E: Error {
    pub name: String,
    #[educe(Debug(ignore))]
    pub call: Arc<dyn StaticFunctionCall<T, E>>,
}

pub trait FunctionCall<T, E> where T: From<Value>, E: Error {
    fn call(&self, this: T, arguments: BTreeMap<String, T>) -> Result<T, E>;
}

impl<T, E, F> FunctionCall<T, E> for F where
    T: From<Value>,
    E: Error,
    F: Fn(T, BTreeMap<String, T>) -> Result<T, E> {
    fn call(&self, this: T, arguments: BTreeMap<String, T>) -> Result<T, E> {
        self(this, arguments)
    }
}

pub trait StaticFunctionCall<T, E> where T: From<Value>, E: Error {
    fn call(&self, arguments: BTreeMap<String, T>) -> Result<T, E>;
}

impl<T, E, F> StaticFunctionCall<T, E> for F where
    T: From<Value>,
    E: Error,
    F: Fn(BTreeMap<String, T>) -> Result<T, E> {
    fn call(&self, arguments: BTreeMap<String, T>) -> Result<T, E> {
        self(arguments)
    }
}

