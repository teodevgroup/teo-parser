use std::error::Error;
use std::fmt::{Display, Formatter, Debug};
use teo_teon::Value;
use crate::fetcher::fetcher_loader::FetcherLoader;

pub(crate) struct FetcherLoaderError {
    message: String
}

impl Display for FetcherLoaderError {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Debug for FetcherLoaderError {

    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for FetcherLoaderError {}

pub(crate) fn default_fetcher_loader() -> FetcherLoader<Option<Value>, FetcherLoaderError> {
    FetcherLoader::new()
}