mod test {
    use teo_parser::{auto_complete_items, parse};

    #[test]
    fn completion_items_for_pipeline_argument_of_pipeline() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/pipeline/schemas/01.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (115, 30));
        assert!(completions.len() >= 80);
    }

    #[test]
    fn completion_items_for_empty_pipeline() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/pipeline/schemas/02.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (115, 28));
        assert!(completions.len() >= 80);
    }

    #[test]
    fn completion_extra_argument_should_not_cause_errors() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/pipeline/schemas/03.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (115, 38));
        assert!(completions.len() >= 80);
    }

    #[test]
    fn completion_from_user_typed_namespace() {
        let path_buf = std::env::current_dir().unwrap().join("tests/auto_completion/pipeline/schemas/04.teo");
        let path = path_buf.to_str().unwrap();
        let (schema, _) = parse(path, None, None);
        let completions = auto_complete_items(&schema, path, (116, 50));
        assert_eq!(completions.len(), 1);
        assert_eq!(completions.first().unwrap().label.as_str(), "myintro");
    }
}