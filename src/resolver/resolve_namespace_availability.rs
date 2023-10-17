use crate::ast::availability::Availability;
use crate::ast::config::Config;
use crate::ast::namespace::Namespace;
use crate::ast::schema::Schema;
use crate::ast::source::Source;
use crate::resolver::resolve_source_availability::{find_availability_in_connector, find_source_connector};

pub(super) fn resolve_namespace_availability(namespace: &Namespace, schema: &Schema, source: &Source) -> Availability {
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