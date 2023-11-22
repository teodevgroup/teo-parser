mod test {
    use teo_parser::{auto_complete_items, parse};

    #[test]
    fn completion_items_for_enum_variant() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/enum_variant_literal/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (22, 14));
        assert_eq!(completions.len(), 2);
    }
}