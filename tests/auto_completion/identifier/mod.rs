mod test {
    use teo_parser::{auto_complete_items, parse};

    #[test]
    fn completion_triggers_for_identifier() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/identifier/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (65, 10));
        assert_eq!(completions.iter().find(|c| c.label.as_str() == "s1").is_some(), true);
        assert_eq!(completions.iter().find(|c| c.label.as_str() == "std").is_some(), true);
    }
}
