#[derive(Copy, Clone, Debug)]
pub(super) struct FlusherState {
    pub(super) processing_index: usize,
}

impl Default for FlusherState {
    fn default() -> Self {
        Self {
            processing_index: 0,
        }
    }
}
