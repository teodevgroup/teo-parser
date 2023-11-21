mod test {
    use teo_parser::{auto_complete_items, parse};

    #[test]
    fn completion_items_for_pipeline_argument_of_pipeline() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/pipeline/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, diagnostics) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (115, 30));
        println!("{:?}", completions);
    }
}