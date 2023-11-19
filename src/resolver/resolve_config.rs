use std::collections::HashSet;
use itertools::Itertools;
use maplit::btreemap;
use crate::ast::config::Config;
use crate::resolver::resolve_expression::resolve_expression;
use crate::resolver::resolver_context::ResolverContext;
use crate::traits::identifiable::Identifiable;
use crate::traits::node_trait::NodeTrait;
use crate::traits::resolved::Resolve;

pub(super) fn resolve_config_references<'a>(config: &'a Config, context: &'a ResolverContext<'a>) {
    let availability = context.current_availability();
    *config.actual_availability.borrow_mut() = availability;
    for unattached_identifier in &config.unattached_identifiers {
        context.insert_diagnostics_error(unattached_identifier.span, "unattached config name");
    }
    context.push_dependency(config.path.clone());
    if let Some(config_declaration) = context.schema.find_config_declaration_by_name(config.keyword().name(), availability) {
        // error for non constant keys
        config.items().iter().for_each(|(k, _)| {
            if k.named_key_without_resolving().is_none() {
                context.insert_diagnostics_error(k.span(), "config item key is not constant");
            }
        });
        let exist_keys: HashSet<&str> = config.items().iter().filter_map(|(k, v)| k.named_key_without_resolving()).collect();
        let defined_keys: HashSet<&str> = config_declaration.fields().map(|f| f.identifier().name()).collect();
        let differences = exist_keys.difference(&defined_keys);
        // undefined items
        for item_name in differences {
            let item = config.dictionary_literal().expressions().find(|e| e.key().named_key_without_resolving() == Some(*item_name)).unwrap();
            context.insert_diagnostics_error(item.key().span(), "undefined config item");
        }
        // duplicated items
        for item in config.items().iter().duplicates_by(|(k, v)| k.named_key_without_resolving().unwrap()) {
            context.insert_diagnostics_error(item.0.span(), "duplicated config item");
        }
        // collect missing
        let mut missing_names = vec![];
        // check each field
        for field in config_declaration.fields() {
            if let Some((_, item)) = config.items().iter().find(|(k, v)| k.named_key_without_resolving().is_some() && k.named_key_without_resolving().unwrap() == field.identifier().name()) {
                context.push_dependency(item.path().clone());
                resolve_expression(item, context, field.type_expr().resolved(), &btreemap! {});
                let r#type = item.resolved().r#type();
                if !r#type.is_undetermined() {
                    if !field.type_expr().resolved().test(r#type) {
                        context.insert_diagnostics_error(item.span(), format!("expect {}, found {}", field.type_expr().resolved(), r#type));
                    }
                }
                context.pop_dependency();
            } else {
                if !field.type_expr().resolved().is_optional() {
                    missing_names.push(field.identifier().name());
                }
            }
        }
        if !missing_names.is_empty() {
            context.insert_diagnostics_error(config.keyword().span, format!("missing required config items: {}", missing_names.join(", ")));
        }
    } else {
        context.insert_diagnostics_error(config.keyword().span, "configuration is undefined");
    }
    context.pop_dependency();
}