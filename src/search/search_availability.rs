use crate::ast::arith::ArithExpr;
use crate::ast::availability::Availability;
use crate::ast::config::Config;
use crate::ast::literals::EnumVariantLiteral;
use crate::ast::namespace::Namespace;
use crate::ast::schema::Schema;
use crate::ast::source::{Source, SourceType};

pub(crate) fn search_availability(schema: &Schema, source: &Source, namespace_path: &Vec<&str>) -> Availability {
    if namespace_path.len() == 0 {
        find_source_availability(schema, source)
    } else {
        if let Some(namespace) = source.find_child_namespace_by_string_path(namespace_path) {
            find_namespace_availability(namespace, schema, source)
        } else {
            Availability::no_database()
        }
    }
}

pub(crate) fn find_source_availability(schema: &Schema, source: &Source) -> Availability {
    if source.r#type == SourceType::Builtin {
        return Availability::default(); // just pretend to be all
    }
    let connector = find_source_connector(schema, source);
    let retval = find_availability_in_connector(connector);
    retval
}

pub(crate) fn find_source_connector<'a>(schema: &'a Schema, source: &'a Source) -> Option<&'a Config> {
    if let Some(connector) = source.get_connector() {
        Some(connector)
    } else {
        source.imports().iter().find_map(|import| {
            if let Some(source) = schema.source_at_path(&import.file_path) {
                source.get_connector()
            } else {
                None
            }
        })
    }
}

pub(crate) fn find_availability_in_connector(connector: Option<&Config>) -> Availability {
    if let Some(connector) = connector {
        if let Some(provider) = connector.items.iter().find(|item| {
            item.identifier.name() == "provider"
        }) {
            if let Some(enum_variant_literal) = provider.expression.kind.as_enum_variant_literal() {
                availability_from_enum_variant_literal(enum_variant_literal)
            } else if let Some(unit) = provider.expression.kind.as_unit() {
                if let Some(enum_variant_literal) = unit.expressions.first().unwrap().kind.as_enum_variant_literal() {
                    availability_from_enum_variant_literal(enum_variant_literal)
                } else {
                    Availability::no_database()
                }
            } else if let Some(arith) = provider.expression.kind.as_arith_expr() {
                match arith {
                    ArithExpr::Expression(e) => {
                        if let Some(unit) = e.kind.as_unit() {
                            if let Some(enum_variant_literal) = unit.expressions.first().unwrap().kind.as_enum_variant_literal() {
                                availability_from_enum_variant_literal(enum_variant_literal)
                            } else {
                                Availability::no_database()
                            }
                        } else if let Some(e) = e.kind.as_enum_variant_literal() {
                            availability_from_enum_variant_literal(e)
                        } else {
                            Availability::no_database()
                        }
                    }
                    _ => Availability::no_database(),
                }
            } else {
                Availability::no_database()
            }
        } else {
            Availability::no_database()
        }
    } else {
        Availability::no_database()
    }
}

pub(crate) fn find_namespace_availability(namespace: &Namespace, schema: &Schema, source: &Source) -> Availability {
    if source.r#type == SourceType::Builtin {
        return Availability::default(); // just pretend to be all
    }
    let connector = find_namespace_connector(namespace, schema, source);
    find_availability_in_connector(connector)
}

pub(crate) fn find_namespace_connector<'a>(namespace: &'a Namespace, schema: &'a Schema, source: &'a Source) -> Option<&'a Config> {
    // Namespace
    // Imported files same namespace
    // Parent namespace
    // Imported files parent namespace
    // Source file
    // Imported source files
    if let Some(connector) = namespace.get_connector() {
        Some(connector)
    } else {
        let connector = source.imports().iter().find_map(|import| {
            if let Some(source) = schema.source_at_path(&import.file_path) {
                if let Some(namespace) = source.find_child_namespace_by_string_path(&namespace.str_path()) {
                    namespace.get_connector()
                } else {
                    None
                }
            } else {
                None
            }
        });
        if let Some(connector) = connector {
            return Some(connector);
        }
        let mut parent_namespace = source.parent_namespace_for_namespace(namespace);
        loop {
            if parent_namespace.is_some() {
                if let Some(connector) = parent_namespace.unwrap().get_connector() {
                    return Some(connector);
                } else {
                    let connector = source.imports().iter().find_map(|import| {
                        if let Some(source) = schema.source_at_path(&import.file_path) {
                            if let Some(namespace) = source.find_child_namespace_by_string_path(&namespace.str_path()) {
                                namespace.get_connector()
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    });
                    if let Some(connector) = connector {
                        return Some(connector);
                    }
                }
                parent_namespace = source.parent_namespace_for_namespace(parent_namespace.unwrap());
            } else {
                break
            }
        }
        return find_source_connector(schema, source);
    }
}

fn availability_from_enum_variant_literal(e: &EnumVariantLiteral) -> Availability {
    match e.identifier.name() {
        "mongo" => Availability::mongo(),
        "mysql" => Availability::mysql(),
        "postgres" => Availability::postgres(),
        "sqlite" => Availability::sqlite(),
        _ => Availability::no_database(),
    }
}