use crate::format::Writer;

pub trait Write {

    fn write(&self, writer: &mut Writer);

    fn write_output_with_default_writer(&self) -> String {
        let mut writer = Writer::default();
        self.write(&mut writer);
        writer.output()
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

    fn is_block_start(&self) -> bool {
        false
    }

    fn is_block_end(&self) -> bool {
        false
    }

    fn wrap(&self, content: &str, available_length: usize) -> String {
        content.to_owned()
    }

    fn always_start_on_new_line(&self) -> bool {
        false
    }
}
