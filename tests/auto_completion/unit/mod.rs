mod test {
    use teo_parser::{auto_complete_items, parse};

    #[test]
    fn completion_items_for_unit() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/unit/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (68, 22));
        assert_eq!(completions.len(), 2);
        assert_eq!(completions.first().unwrap().label.as_str(), "provider");
        assert_eq!(completions.get(1).unwrap().label.as_str(), "url");
    }

    #[test]
    fn completion_items_for_unit_with_constant_reference_item() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/unit/schemas/02.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (68, 20));
        assert_eq!(completions.len(), 1);
        assert_eq!(completions.first().unwrap().label.as_str(), "subscript");
    }

}