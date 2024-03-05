mod test {
    use teo_parser::diagnostics::printer::print_diagnostics;
    use teo_parser::parse;

    #[test]
    fn synthesized_interface_enums_should_be_no_error() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/struct_subscription/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        assert_eq!(diagnostics.has_errors(), false);
        assert_eq!(diagnostics.has_warnings(), false);
    }

    #[test]
    fn env_subscription_should_not_change_current_namespace() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/struct_subscription/schemas/02.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        print_diagnostics(&diagnostics, true);
        assert_eq!(diagnostics.has_errors(), false);
        assert_eq!(diagnostics.has_warnings(), false);
    }
}