use crate::ast::generics::GenericsDeclaration;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::type_expr::{TypeBinaryOp, TypeExpr, TypeExprKind, TypeItem, TypeSubscript, TypeTuple};
use crate::completion::completion_item::CompletionItem;

#[derive(Copy, Clone, Debug)]
pub(super) enum TypeExprFilter {
    None,
    Model,
    ActionInput,
}

pub(super) fn find_completion_in_type_expr(schema: &Schema, source: &Source, type_expr: &TypeExpr, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter) -> Vec<CompletionItem> {
    find_completion_in_type_expr_kind(schema, source, &type_expr.kind, line_col, generics, filter)
}

fn find_completion_in_type_expr_kind(schema: &Schema, source: &Source, kind: &TypeExprKind, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter) -> Vec<CompletionItem> {
    match kind {
        TypeExprKind::Expr(kind) => find_completion_in_type_expr_kind(schema, source, kind.as_ref(), line_col, generics, filter),
        TypeExprKind::BinaryOp(binary_op) => find_completion_in_type_expr_binary_op(schema, source, binary_op, line_col, generics, filter),
        TypeExprKind::TypeItem(item) => find_completion_in_type_item(schema, source, item, line_col, generics, filter),
        TypeExprKind::TypeGroup(group) => find_completion_in_type_expr_kind(schema, source, group.kind.as_ref(), line_col, generics, filter),
        TypeExprKind::TypeTuple(tuple) => find_completion_in_type_tuple(schema, source, tuple, line_col, generics, filter),
        TypeExprKind::TypeSubscript(subscript) => find_completion_in_type_subscript(schema, source, subscript, line_col, generics, filter),
        TypeExprKind::FieldReference(_) => vec![],
    }
}

fn find_completion_in_type_expr_binary_op(schema: &Schema, source: &Source, binary_op: &TypeBinaryOp, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter) -> Vec<CompletionItem> {
    if binary_op.lhs.as_ref().span().contains_line_col(line_col) {
        find_completion_in_type_expr_kind(schema, source, binary_op.lhs.as_ref(), line_col, generics, filter)
    } else if binary_op.rhs.as_ref().span().contains_line_col(line_col) {
        find_completion_in_type_expr_kind(schema, source, binary_op.rhs.as_ref(), line_col, generics, filter)
    } else {
        vec![]
    }
}

fn find_completion_in_type_tuple(schema: &Schema, source: &Source, tuple: &TypeTuple, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter) -> Vec<CompletionItem> {
    for kind in &tuple.kinds {
        if kind.span().contains_line_col(line_col) {
            return find_completion_in_type_expr_kind(schema, source, kind, line_col, generics, filter);
        }
    }
    vec![]
}

fn find_completion_in_type_subscript(schema: &Schema, source: &Source, subscript: &TypeSubscript, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter) -> Vec<CompletionItem> {
    if subscript.type_expr.span().contains_line_col(line_col) {
        find_completion_in_type_expr_kind(schema, source, subscript.type_expr.as_ref(), line_col, generics, filter)
    } else if subscript.type_item.span.contains_line_col(line_col) {
        find_completion_in_type_item(schema, source, subscript.type_item.as_ref(), line_col, generics, filter)
    } else {
        vec![]
    }
}

fn find_completion_in_type_item(schema: &Schema, source: &Source, item: &TypeItem, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter) -> Vec<CompletionItem> {
    for generic_kind in &item.generics {
        if generic_kind.span().contains_line_col(line_col) {
            return find_completion_in_type_expr_kind(schema, source, generic_kind, line_col, generics, filter);
        }
    }
    if item.identifier_path.span.contains_line_col(line_col) {
        return find_completion_in_type_item_identifier_path(schema, source, &item.identifier_path, line_col, generics, filter);
    }
    vec![]
}

fn find_completion_in_type_item_identifier_path(schema: &Schema, source: &Source, identifier_path: &IdentifierPath, line_col: (usize, usize), generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter) -> Vec<CompletionItem> {

    vec![]
}