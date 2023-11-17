use std::fmt::Debug;
use crate::format::Writer;

pub trait Write: Debug {

    fn write<'a>(&'a self, writer: &mut Writer<'a>);

    fn write_output_with_default_writer(&self) -> String {
        let mut writer = Writer::default();
        self.write(&mut writer);
        writer.flush()
    }

    fn prefer_whitespace_before(&self) -> bool {
        false
    }

    fn prefer_whitespace_after(&self) -> bool {
        false
    }

    fn prefer_always_no_whitespace_before(&self) -> bool {
        false
    }

    fn always_start_on_new_line(&self) -> bool {
        false
    }

    fn always_end_on_new_line(&self) -> bool {
        false
    }

    fn is_block_start(&self) -> bool {
        false
    }

    fn is_block_end(&self) -> bool {
        false
    }

    fn is_block_element_delimiter(&self) -> bool {
        false
    }

    fn is_block_level_element(&self) -> bool {
        false
    }

    fn wrap(&self, content: &str, _available_length: usize) -> String {
        content.to_owned()
    }
}
