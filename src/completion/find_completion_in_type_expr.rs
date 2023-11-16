use crate::availability::Availability;
use crate::ast::generics::GenericsDeclaration;
use crate::ast::identifier_path::IdentifierPath;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::ast::type_expr::{TypeBinaryOperation, TypeExpr, TypeExprKind, TypeItem, TypeSubscript, TypeTuple};
use crate::completion::completion_item::CompletionItem;
use crate::completion::find_top_completion_with_filter::find_top_completion_with_filter;
use crate::utils::top_filter::top_filter_for_type_expr_filter;

#[derive(Copy, Clone, Debug)]
pub enum TypeExprFilter {
    None,
    Model,
    ActionInput,
}

impl TypeExprFilter {

    pub(crate) fn is_none(&self) -> bool {
        match self {
            Self::None => true,
            _ => false,
        }
    }

    pub(crate) fn is_model(&self) -> bool {
        match self {
            Self::Model => true,
            _ => false,
        }
    }

    pub(crate) fn is_action_input(&self) -> bool {
        match self {
            Self::ActionInput => true,
            _ => false,
        }
    }
}

pub(super) fn find_completion_in_type_expr(schema: &Schema, source: &Source, type_expr: &TypeExpr, line_col: (usize, usize), namespace_path: &Vec<&str>, generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter, availability: Availability) -> Vec<CompletionItem> {
    find_completion_in_type_expr_kind(schema, source, &type_expr.kind, line_col, namespace_path, generics, filter, availability)
}

fn find_completion_in_type_expr_kind(schema: &Schema, source: &Source, kind: &TypeExprKind, line_col: (usize, usize), namespace_path: &Vec<&str>, generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter, availability: Availability) -> Vec<CompletionItem> {
    match kind {
        TypeExprKind::Expr(kind) => find_completion_in_type_expr_kind(schema, source, kind.as_ref(), line_col, namespace_path, generics, filter, availability),
        TypeExprKind::BinaryOp(binary_op) => find_completion_in_type_expr_binary_op(schema, source, binary_op, line_col, namespace_path, generics, filter, availability),
        TypeExprKind::TypeItem(item) => find_completion_in_type_item(schema, source, item, line_col, namespace_path, generics, filter, availability),
        TypeExprKind::TypeGroup(group) => find_completion_in_type_expr_kind(schema, source, group.kind.as_ref(), line_col, namespace_path, generics, filter, availability),
        TypeExprKind::TypeTuple(tuple) => find_completion_in_type_tuple(schema, source, tuple, line_col, namespace_path, generics, filter, availability),
        TypeExprKind::TypeSubscript(subscript) => find_completion_in_type_subscript(schema, source, subscript, line_col, namespace_path, generics, filter, availability),
        TypeExprKind::FieldName(_) => vec![],
    }
}

fn find_completion_in_type_expr_binary_op(schema: &Schema, source: &Source, binary_op: &TypeBinaryOperation, line_col: (usize, usize), namespace_path: &Vec<&str>, generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter, availability: Availability) -> Vec<CompletionItem> {
    if binary_op.lhs().span().contains_line_col(line_col) {
        find_completion_in_type_expr_kind(schema, source, binary_op.lhs(), line_col, namespace_path, generics, filter, availability)
    } else if binary_op.rhs().span().contains_line_col(line_col) {
        find_completion_in_type_expr_kind(schema, source, binary_op.rhs(), line_col, namespace_path, generics, filter, availability)
    } else {
        vec![]
    }
}

fn find_completion_in_type_tuple(schema: &Schema, source: &Source, tuple: &TypeTuple, line_col: (usize, usize), namespace_path: &Vec<&str>, generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter, availability: Availability) -> Vec<CompletionItem> {
    for kind in &tuple.items {
        if kind.span().contains_line_col(line_col) {
            return find_completion_in_type_expr_kind(schema, source, kind, line_col, namespace_path, generics, filter, availability);
        }
    }
    vec![]
}

fn find_completion_in_type_subscript(schema: &Schema, source: &Source, subscript: &TypeSubscript, line_col: (usize, usize), namespace_path: &Vec<&str>, generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter, availability: Availability) -> Vec<CompletionItem> {
    if subscript.type_expr.span().contains_line_col(line_col) {
        find_completion_in_type_expr_kind(schema, source, subscript.type_expr.as_ref(), line_col, namespace_path, generics, filter, availability)
    } else if subscript.type_item.span.contains_line_col(line_col) {
        find_completion_in_type_item(schema, source, &subscript.type_item, line_col, namespace_path, generics, filter, availability)
    } else {
        vec![]
    }
}

fn find_completion_in_type_item(schema: &Schema, source: &Source, item: &TypeItem, line_col: (usize, usize), namespace_path: &Vec<&str>, generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter, availability: Availability) -> Vec<CompletionItem> {
    for generic_kind in &item.generics {
        if generic_kind.span().contains_line_col(line_col) {
            return find_completion_in_type_expr_kind(schema, source, generic_kind, line_col, namespace_path, generics, filter, availability);
        }
    }
    if item.identifier_path.span.contains_line_col(line_col) {
        return find_completion_in_type_item_identifier_path(schema, source, &item.identifier_path, line_col, namespace_path, generics, filter, availability);
    }
    vec![]
}

fn find_completion_in_type_item_identifier_path(schema: &Schema, source: &Source, identifier_path: &IdentifierPath, line_col: (usize, usize), namespace_path: &Vec<&str>, generics: &Vec<&GenericsDeclaration>, filter: TypeExprFilter, availability: Availability) -> Vec<CompletionItem> {
    let mut user_typed_spaces = vec![];
    for identifier in identifier_path.identifiers() {
        if identifier.span.contains_line_col(line_col) {
            break
        } else {
            user_typed_spaces.push(identifier.name());
        }
    }
    let mut results = vec![];
    if identifier_path.identifiers.len() == 1 {
        results.extend(builtin_types(filter));
        results.extend(completion_items_from_generics(generics));
    }
    results.extend(find_completion_for_referenced_types_with_filter(schema, source, namespace_path, &user_typed_spaces, filter, availability));
    results
}

fn find_completion_for_referenced_types_with_filter(schema: &Schema, source: &Source, namespace_path: &Vec<&str>, user_typed_spaces: &Vec<&str>, filter: TypeExprFilter, availability: Availability) -> Vec<CompletionItem> {
    find_top_completion_with_filter(schema, source, namespace_path, user_typed_spaces, &top_filter_for_type_expr_filter(filter), availability)
}

fn completion_items_from_generics(generics: &Vec<&GenericsDeclaration>) -> Vec<CompletionItem> {
    let mut result = vec![];
    for gen in generics {
        for i in &gen.identifiers {
            result.push(CompletionItem {
                label: i.name().to_owned(),
                namespace_path: None,
                documentation: None,
                detail: None,
            });
        }
    }
    result
}

fn builtin_types(filter: TypeExprFilter) -> Vec<CompletionItem> {
    let mut result = vec![];
    if !filter.is_model() {
        result.push(builtin_type("Any"));
    }
    if filter.is_none() {
        result.push(builtin_type("Ignored"));
        result.push(builtin_type("Null"));
        result.push(builtin_type("File"));
        result.push(builtin_type("Regex"));
        result.push(builtin_type("Model"));
        result.push(builtin_type("DataSet"));
        result.push(builtin_type("Enumerable"));
        result.push(builtin_type("Dictionary"));
        result.push(builtin_type("Tuple"));
        result.push(builtin_type("Range"));
        result.push(builtin_type("Union"));
        result.push(builtin_type("ModelScalarFields"));
        result.push(builtin_type("ModelScalarFieldsWithoutVirtuals"));
        result.push(builtin_type("ModelSerializableScalarFields"));
        result.push(builtin_type("ModelRelations"));
        result.push(builtin_type("ModelDirectRelations"));
        result.push(builtin_type("DataSetRecord"));
        result.push(builtin_type("FieldType"));
        result.push(builtin_type("Pipeline"));
    }
    if !filter.is_action_input() {
        result.push(builtin_type("Bool"));
        result.push(builtin_type("Int"));
        result.push(builtin_type("Int64"));
        result.push(builtin_type("Float"));
        result.push(builtin_type("Float32"));
        result.push(builtin_type("Decimal"));
        result.push(builtin_type("ObjectId"));
        result.push(builtin_type("String"));
        result.push(builtin_type("Date"));
        result.push(builtin_type("DateTime"));
        result.push(builtin_type("Array"));
        result.push(builtin_type("Optional"));
    }
    result
}

fn builtin_type(name: &str) -> CompletionItem {
    CompletionItem {
        label: name.to_owned(),
        namespace_path: Some("builtin".to_owned()),
        documentation: None,
        detail: None,
    }
}