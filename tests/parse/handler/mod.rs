mod test {
    use teo_parser::diagnostics::diagnostics::DiagnosticsLog;
    use teo_parser::parse;

    #[test]
    fn get_handler_with_arguments_should_error() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/handler/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        assert_eq!(diagnostics.errors().len(), 1);
        assert_eq!(diagnostics.has_warnings(), false);
        assert!(diagnostics.errors().iter().all(|e| e.message() == "get or delete handler requires no input type"));
    }

    #[test]
    fn normal_handler_without_arguments_should_error() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/handler/schemas/02.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        assert_eq!(diagnostics.errors().len(), 2);
        assert_eq!(diagnostics.has_warnings(), false);
        assert!(diagnostics.errors().iter().all(|e| e.message() == "handler requires input type"));
    }
}