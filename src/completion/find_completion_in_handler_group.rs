use crate::ast::handler::{HandlerDeclaration, HandlerGroupDeclaration};
use crate::ast::info_provider::InfoProvider;
use crate::ast::reference::ReferenceType;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_completion_in_decorator::{find_completion_in_decorator, find_completion_in_empty_decorator};
use crate::completion::find_completion_in_type_expr::{find_completion_in_type_expr, TypeExprFilter};

pub(super) fn find_completion_in_handler_group_declaration(schema: &Schema, source: &Source, handler_group_declaration: &HandlerGroupDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    for handler_declaration in &handler_group_declaration.handler_declarations {
        if handler_declaration.span.contains_line_col(line_col) {
            return find_completion_in_handler_declaration(schema, source, handler_declaration, line_col);
        }
    }
    vec![]
}

pub(super) fn find_completion_in_handler_declaration(schema: &Schema, source: &Source, handler_declaration: &HandlerDeclaration, line_col: (usize, usize)) -> Vec<CompletionItem> {
    if handler_declaration.input_type.span().contains_line_col(line_col) {
        return find_completion_in_type_expr(schema, source, &handler_declaration.input_type, line_col, &handler_declaration.namespace_str_path(), &vec![], TypeExprFilter::ActionInput);
    }
    if handler_declaration.output_type.span().contains_line_col(line_col) {
        return find_completion_in_type_expr(schema, source, &handler_declaration.output_type, line_col, &handler_declaration.namespace_str_path(), &vec![], TypeExprFilter::ActionInput);
    }
    for decorator in &handler_declaration.decorators {
        if decorator.span.contains_line_col(line_col) {
            return find_completion_in_decorator(schema, source, decorator, &handler_declaration.namespace_str_path(), line_col, ReferenceType::HandlerDecorator);
        }
    }
    for empty_decorator_span in &handler_declaration.empty_decorators_spans {
        if empty_decorator_span.contains_line_col(line_col) {
            return find_completion_in_empty_decorator(schema, source, &handler_declaration.namespace_str_path(), ReferenceType::HandlerDecorator);
        }
    }
    vec![]
}