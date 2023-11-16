use crate::ast::decorator_declaration::DecoratorDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_argument_list_declaration::find_completion_in_argument_list_declaration;
use crate::traits::info_provider::InfoProvider;

pub(super) fn find_completion_in_decorator_declaration(schema: &Schema, source: &Source, decorator_declaration: &DecoratorDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if let Some(argument_list_declaration) = decorator_declaration.argument_list_declaration() {
        if argument_list_declaration.span.contains_line_col(line_col) {
            return find_completion_in_argument_list_declaration(schema, source, argument_list_declaration, line_col, &decorator_declaration.generics_declaration.iter().collect(), &decorator_declaration.namespace_str_path(), decorator_declaration.define_availability);
        }
    }
    for variant in &decorator_declaration.variants {
        if let Some(argument_list_declaration) = variant.argument_list_declaration() {
            if argument_list_declaration.span.contains_line_col(line_col) {
                return find_completion_in_argument_list_declaration(schema, source, argument_list_declaration, line_col, &decorator_declaration.generics_declaration.iter().collect(), &decorator_declaration.namespace_str_path(), decorator_declaration.define_availability);
            }
        }
    }
    vec![]
}

