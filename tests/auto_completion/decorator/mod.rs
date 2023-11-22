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
}
