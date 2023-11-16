use crate::ast::argument_declaration::{ArgumentDeclaration};
use crate::ast::argument_list_declaration::ArgumentListDeclaration;
use crate::availability::Availability;
use crate::ast::generics::GenericsDeclaration;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_type_expr::{find_completion_in_type_expr, TypeExprFilter};

pub(super) fn find_completion_in_argument_list_declaration(schema: &Schema, source: &Source, argument_list_declaration: &ArgumentListDeclaration, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>, namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    for argument_declaration in argument_list_declaration.argument_declarations() {
        if argument_declaration.span.contains_line_col(line_col) {
            return find_completion_in_argument_declaration(schema, source, argument_declaration, line_col, generics, namespace_path, availability);
        }
    }
    vec![]
}

pub(super) fn find_completion_in_argument_declaration(schema: &Schema, source: &Source, argument_declaration: &ArgumentDeclaration, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>, namespace_path: &Vec<&str>, availability: Availability) -> Vec<CompletionItem> {
    if argument_declaration.type_expr().span().contains_line_col(line_col) {
        return find_completion_in_type_expr(schema, source, argument_declaration.type_expr(), line_col, namespace_path, generics, TypeExprFilter::None, availability);
    }
    vec![]
}