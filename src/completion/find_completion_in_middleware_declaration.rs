use crate::ast::availability::Availability;
use crate::ast::middleware::MiddlewareDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_argument_list_declaration::find_completion_in_argument_list_declaration;
use crate::traits::info_provider::InfoProvider;

pub(super) fn find_completion_in_middleware_declaration(schema: &Schema, source: &Source, middleware_declaration: &MiddlewareDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if let Some(argument_list_declaration) = &middleware_declaration.argument_list_declaration {
        if argument_list_declaration.span.contains_line_col(line_col) {
            return find_completion_in_argument_list_declaration(schema, source, argument_list_declaration, line_col, &vec![], &middleware_declaration.namespace_str_path(), Availability::default());
        }
    }
    vec![]
}