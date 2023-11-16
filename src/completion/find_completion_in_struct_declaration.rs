use crate::ast::function_declaration::FunctionDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::struct_declaration::StructDeclaration;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_argument_list_declaration::find_completion_in_argument_list_declaration;
use crate::completion::find_completion_in_type_expr::{find_completion_in_type_expr, TypeExprFilter};
use crate::traits::info_provider::InfoProvider;

pub(super) fn find_completion_in_struct_declaration(schema: &Schema, source: &Source, struct_declaration: &StructDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    for function_declaration in struct_declaration.function_declarations() {
        if function_declaration.span.contains_line_col(line_col) {
            return find_completion_in_function_declaration(schema, source, struct_declaration, function_declaration, line_col);
        }
    }
    vec![]
}

fn find_completion_in_function_declaration(schema: &Schema, source: &Source, struct_declaration: &StructDeclaration, function_declaration: &FunctionDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if function_declaration.span.contains_line_col(line_col) {
        let mut generics = vec![];
        generics.extend(struct_declaration.generics_declaration.iter());
        generics.extend(function_declaration.generics_declaration.iter());
        if function_declaration.argument_list_declaration().span.contains_line_col(line_col) {
            return find_completion_in_argument_list_declaration(schema, source, function_declaration.argument_list_declaration(), line_col, &generics, &function_declaration.namespace_str_path(), function_declaration.define_availability);
        }
        if function_declaration.return_type.span().contains_line_col(line_col) {
            return find_completion_in_type_expr(schema, source, function_declaration.return_type(), line_col, &function_declaration.namespace_str_path(), &generics, TypeExprFilter::None, function_declaration.define_availability);
        }
    }
    vec![]
}