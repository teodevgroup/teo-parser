// pub(crate) fn jump_to_definition(&self, context: &DefinitionContext, line_col: (usize, usize)) -> Vec<Definition> {
//     if self.source.span.contains_line_col(line_col) {
//         if !self.file_path.starts_with("(builtin)") {
//             vec![
//                 Definition {
//                     path: self.file_path.clone(),
//                     selection_span: self.source.span,
//                     target_span: Span::default(),
//                     identifier_span: Span::default(),
//                 }
//             ]
//         } else {
//             vec![]
//         }
//     } else {
//         vec![]
//     }
// }