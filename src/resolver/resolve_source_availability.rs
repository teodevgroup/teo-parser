use crate::ast::availability::Availability;
use crate::ast::config::Config;
use crate::ast::schema::Schema;
use crate::ast::source::Source;

pub(super) fn resolve_source_availability(schema: &Schema, source: &Source) -> Availability {
    let connector = find_source_connector(schema, source);
    find_availability_in_connector(connector)
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
                match enum_variant_literal.identifier.name() {
                    "mongo" => Availability::mongo(),
                    "mysql" => Availability::mysql(),
                    "postgres" => Availability::postgres(),
                    "sqlite" => Availability::sqlite(),
                    _ => Availability::none(),
                }
            } else {
                Availability::none()
            }
        } else {
            Availability::none()
        }
    } else {
        Availability::none()
    }
}