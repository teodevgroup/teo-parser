use crate::ast::data_set::{DataSet, DataSetGroup, DataSetGroupResolved, DataSetResolved};
use crate::resolver::resolve_identifier::resolve_identifier_path_with_filter;
use crate::resolver::resolver_context::{ExaminedDataSetRecord, ResolverContext};
use crate::utils::top_filter::top_filter_for_model;

pub(super) fn resolve_data_set<'a>(data_set: &'a DataSet, context: &'a ResolverContext<'a>) {
    let actual_availability = context.current_availability();
    if context.has_examined_default_path(&data_set.string_path, data_set.define_availability) {
        context.insert_duplicated_identifier(data_set.identifier.span);
    }
    data_set.resolve(DataSetResolved {
        actual_availability
    });
    for group in &data_set.groups {
        resolve_data_set_group(data_set, group, context);
    }
}

fn resolve_data_set_group<'a>(data_set: &'a DataSet, group: &'a DataSetGroup, context: &'a ResolverContext<'a>) {
    if let Some(reference) = resolve_identifier_path_with_filter(&group.identifier_path, context, &top_filter_for_model(), context.current_availability()) {
        let model = context.schema.find_top_by_path(&reference).unwrap().as_model().unwrap();
        group.resolve(DataSetGroupResolved {
            model_path: reference,
            model_string_path: model.string_path.clone(),
            actual_availability: context.current_availability(),
        });
    } else {
        context.insert_diagnostics_error(group.identifier_path.span, "model not found");
    }
    // record each record names
    for record in &group.records {
        let examined = ExaminedDataSetRecord {
            data_set: data_set.string_path.clone(),
            group: group.resolved().model_string_path.clone(),
            record: record.identifier.name().to_owned(),
        };
        if context.has_examined_data_set_record(&examined) {
            context.insert_diagnostics_error(record.identifier.span, "duplicated record");
        }
        context.add_examined_data_set_record(examined);
    }
}

pub(super) fn resolve_data_set_records<'a>(data_set: &'a DataSet, context: &'a ResolverContext<'a>) {

}