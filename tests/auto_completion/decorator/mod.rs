mod test {
    use teo_parser::{auto_complete_items, parse};

    #[test]
    fn completion_triggers_from_dot() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/decorator/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (115, 41));
        assert_eq!(completions.len(), 1);
        assert_eq!(completions.first().unwrap().label.as_str(), "mygod");
    }

    #[test]
    fn completion_should_adapt_to_current_availability() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/decorator/schemas/02.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (68, 8));
        assert_eq!(completions.iter().filter(|c| c.label.as_str() == "db").count(), 1);
    }
}
