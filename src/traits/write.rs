use crate::format::Writer;

pub trait Write {

    fn write(&self, writer: &mut Writer);

    fn write_output_with_default_writer(&self) -> String {
        let mut writer = Writer::default();
        self.write(&mut writer);
        writer.output()
    }
}
