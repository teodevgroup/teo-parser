use std::fmt::{Display, Debug};
use crate::fetcher::fetcher_loader::FetcherLoader;

pub(crate) fn default_fetcher_loader() -> FetcherLoader {
    FetcherLoader::new()
}