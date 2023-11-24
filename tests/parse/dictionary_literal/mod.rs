mod test {
    use teo_parser::diagnostics::diagnostics::DiagnosticsLog;
    use teo_parser::parse;

    #[test]
    fn dictionary_literals_should_error_if_object_key_is_invalid() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/dictionary_literal/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        assert_eq!(diagnostics.errors().len(), 2);
        assert_eq!(diagnostics.has_warnings(), false);
        assert!(diagnostics.errors().iter().all(|e| e.message() == "identifier not found"));
    }
}