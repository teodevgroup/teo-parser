mod test {
    use teo_parser::{parse, print_to_terminal, generate_json_diagnostics};

    #[test]
    fn print() {
        let (_, diagnostics) = parse("test.teo", None, None);
        print_to_terminal(&diagnostics);
    }

    #[test]
    fn lint_to_json() {
        let (_, diagnostics) = parse("/Users/victor/Developer/teo-namespace-example/data.teo", None, None);
        let result = generate_json_diagnostics(&diagnostics, true);
        println!("{}", result)
    }
}