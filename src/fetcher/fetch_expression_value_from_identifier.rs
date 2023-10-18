// use teo_teon::Value;
// use crate::ast::availability::Availability;
// use crate::ast::schema::Schema;
// use crate::ast::top::Top;
// use crate::fetcher::fetch_expression_value::fetch_expression_value;
// use crate::r#type::r#type::Type;
//
// fn track_path_upwards_into_value<'a>(path: &Vec<usize>, schema: &Schema, availability: Availability, expect: &Type) -> Result<Option<Value>, String> {
//     let top = schema.find_top_by_path(path).unwrap();
//     match top {
//         Top::Config(c) => Ok(None),
//         Top::Constant(c) => {
//             fetch_expression_value(
//                 &c.expression,
//
//             )
//             if !c.is_resolved() {
//                 resolve_constant(c, context);
//             }
//             c.resolved().r#type.clone()
//         }
//         Top::Enum(e) => Ok(None),
//         Top::Model(m) => Ok(None),
//         Top::Interface(i) => Ok(None),
//         Top::Namespace(n) => Ok(None),
//         _ => unreachable!(),
//     }
// }