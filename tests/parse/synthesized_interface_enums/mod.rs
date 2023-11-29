mod test {
    use teo_parser::diagnostics::printer::print_diagnostics;
    use teo_parser::parse;

    #[test]
    fn synthesized_interface_enums_should_be_no_error() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/synthesized_interface_enums/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        print_diagnostics(&diagnostics, true);
        assert_eq!(diagnostics.has_errors(), false);
        assert_eq!(diagnostics.has_warnings(), false);
    }
}