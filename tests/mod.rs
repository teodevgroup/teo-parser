mod test {
    use teo_parser::{parse, print_to_terminal};

    #[test]
    fn print() {
        let (_, diagnostics) = parse("test.teo");
        print_to_terminal(&diagnostics);
    }
}