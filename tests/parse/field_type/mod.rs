mod test {
    use teo_parser::ast::span::Span;
    use teo_parser::diagnostics::diagnostics::DiagnosticsLog;
    use teo_parser::diagnostics::printer::print_diagnostics;
    use teo_parser::parse;

    #[test]
    fn self_get_correct_field_type_should_be_no_errors() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/field_type/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        print_diagnostics(&diagnostics, true);
        assert_eq!(diagnostics.has_errors(), false);
        assert_eq!(diagnostics.has_warnings(), false);
    }

    #[test]
    fn self_get_incorrect_existing_field_type_should_be_a_type_error() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/field_type/schemas/02.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        assert_eq!(diagnostics.has_errors(), true);
        assert_eq!(diagnostics.has_warnings(), false);
        let error = diagnostics.errors().first().unwrap();
        assert_eq!(error.message(), "unexpected pipeline output: expect String?, found Int?");
        assert_eq!(*error.span(), Span {
            start: 176,
            end: 190,
            start_position: (13, 10),
            end_position: (13, 24),
        });
    }

    #[test]
    fn self_get_incorrect_unexisting_field_type_should_be_a_hint_error_and_a_type_error() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/field_type/schemas/03.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        print_diagnostics(&diagnostics, true);
        assert_eq!(diagnostics.has_errors(), true);
        assert_eq!(diagnostics.has_warnings(), false);
        assert_eq!(diagnostics.errors().len(), 2);
        let first_error = diagnostics.errors().first().unwrap();
        let second_error = diagnostics.errors().get(1).unwrap();
        assert_eq!(first_error.message(), "type .kyo doesn't satisfy ScalarFields<Song>");
        assert_eq!(second_error.message(), "unexpected pipeline output: expect String?, found Undetermined?");
    }

    #[test]
    fn self_set_incorrect_existing_field_type_should_be_a_hint_error() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/field_type/schemas/04.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        assert_eq!(diagnostics.has_errors(), true);
        assert_eq!(diagnostics.has_warnings(), false);
        assert_eq!(diagnostics.errors().len(), 1);
        let first_error = diagnostics.errors().first().unwrap();
        assert_eq!(first_error.message(), "expect String, found Int");
    }

    #[test]
    fn self_set_correct_existing_field_type_should_be_ok() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/field_type/schemas/05.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        print_diagnostics(&diagnostics, true);
        assert_eq!(diagnostics.has_errors(), false);
        assert_eq!(diagnostics.has_warnings(), false);
    }

    #[test]
    fn self_set_incorrect_unexisting_field_type_should_be_a_hint_error() {
        let path_buf = std::env::current_dir().unwrap().join("tests/parse/field_type/schemas/06.teo");
        let path = path_buf.to_str().unwrap();
        let (_, diagnostics) = parse(path, None, None);
        assert_eq!(diagnostics.has_errors(), true);
        assert_eq!(diagnostics.has_warnings(), false);
        assert_eq!(diagnostics.errors().len(), 1);
        let first_error = diagnostics.errors().first().unwrap();
        assert_eq!(first_error.message(), "type .iori doesn't satisfy ScalarFields<Song>");
    }
}