mod test {
    use teo_parser::diagnostics::diagnostics::DiagnosticsLog;
    use teo_parser::parse;

    #[test]
    fn errors_if_data_set_group_is_not_found() {
        let path_buf = std::env::current_dir().unwrap().join("tests/file_splitting/data_set_groups/schemas/data.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        diagnostics.errors().iter().for_each(|e| {
            assert_eq!(e.message(), "model not found");
        });
        assert_eq!(14, diagnostics.errors().len());
    }

    #[test]
    fn errors_if_parent_file_is_loaded_and_data_set_group_is_not_found() {
        let path_buf = std::env::current_dir().unwrap().join("tests/file_splitting/data_set_groups/schemas/schema.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        diagnostics.errors().iter().for_each(|e| {
            assert_eq!(e.message(), "model not found");
        });
        assert_eq!(14, diagnostics.errors().len());    }
}
