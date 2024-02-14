pub mod parse;
pub mod jump_to_definition;
pub mod auto_completion;
pub mod format;
pub mod file_splitting;

mod test {

    // #[test]
    // fn test_jump_to_definition() {
    //     let path = "/Users/victor/Developer/teo-namespace-example/part.teo";
    //     let (schema, _) = parse(path, None, None);
    //     let definitions = jump_to_definition(&schema, path, (8, 17));
    // }
    //
    // use backtrace_on_stack_overflow;
    // #[test]
    // fn test_formatting() {
    //     println!("test formatting start");
    //     // unsafe { backtrace_on_stack_overflow::enable() };
    //     let path = "/Users/victor/Developer/hello-teo/schema.teo";
    //     let (schema, _) = parse(path, None, None);
    //     let _result = format_document(&schema, "/Users/victor/Developer/hello-teo/schema.teo");
    // }
}