mod test {
    use teo_parser::{auto_complete_items, parse};

    #[test]
    fn completion_triggers_for_names() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/argument_list/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (27, 34));
        assert_eq!(completions.iter().find(|c| c.label.as_str() == "references").is_some(), true);
    }
}
