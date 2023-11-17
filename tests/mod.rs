mod test {
    use teo_parser::{parse, print_to_terminal, generate_json_diagnostics, auto_complete_items, jump_to_definition};
    use teo_parser::format::format::format_document;

    #[test]
    fn print() {
        let (_, diagnostics) = parse("test.teo", None, None);
        print_to_terminal(&diagnostics);
    }

    #[test]
    fn lint_to_json() {
        let (_, diagnostics) = parse("/Users/victor/Developer/teo-namespace-example/schema.teo", None, None);
        let result = generate_json_diagnostics(&diagnostics, true);
        println!("{}", result)
    }

    #[test]
    fn print_dup() {
        let (_, diagnostics) = parse("/Users/victor/Developer/teo-namespace-example/schema.teo", None, None);
        print_to_terminal(&diagnostics)
    }

    #[test]
    fn auto_completion() {
        let path = "/Users/victor/Developer/teo-namespace-example/part.teo";
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (4, 13));
        println!("{:?}", completions);
    }

    #[test]
    fn test_jump_to_definition() {
        let path = "/Users/victor/Developer/teo-namespace-example/part.teo";
        let (schema, _) = parse(path, None, None);
        let definitions = jump_to_definition(&schema, path, (8, 17));
        println!("{:?}", definitions)
    }

    #[test]
    fn test_auto_completion() {
        let path = "/Users/victor/Developer/teo-namespace-example/schema.teo";
        let (_schema, _) = parse(path, None, None);
        //let completions = auto_complete_items(&schema, path, (4, 13));
        //println!("{:?}", completions);
    }

    #[test]
    fn test_availability() {
        let path = "/Users/victor/Developer/teo-namespace-example/schema.teo";
        let (_schema, _) = parse(path, None, None);
        //let completions = auto_complete_items(&schema, path, (4, 13));
        //println!("{:?}", completions);
    }

    #[test]
    fn test_shape_resolve() {
        let path = "/Users/victor/Developer/teo-namespace-example/shape.teo";
        let (_schema, _) = parse(path, None, None);
        //let completions = auto_complete_items(&schema, path, (4, 13));
        //println!("{:?}", completions);
    }

    use backtrace_on_stack_overflow;
    #[test]
    fn test_formatting() {
        println!("test formatting start");
        // unsafe { backtrace_on_stack_overflow::enable() };
        let path = "/Users/victor/Developer/hello-teo/schema.teo";
        let (schema, _) = parse(path, None, None);
        let _result = format_document(&schema, "/Users/victor/Developer/hello-teo/schema.teo");
    }
}