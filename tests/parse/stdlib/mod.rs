mod test {
    use teo_parser::diagnostics::printer::print_diagnostics;
    use teo_parser::parse;

    #[test]
    fn builtin_std_teo_should_be_no_errors() {
        println!("test formatting start");
        let path = "/Users/victor/Developer/teo-parser/src/builtin/std.teo";
        let (schema, diagnostics) = parse(path, None, None);
        print_diagnostics(&diagnostics, true);
        assert_eq!(diagnostics.has_errors(), false);
        assert_eq!(diagnostics.has_warnings(), false);
    }
}