// static MAP_FILTERS: Lazy<HashSet<&str>> = Lazy::new(|| {
//     hashset! {"equals", "has", "hasEvery", "hasSome", "isEmpty", "length", "hasKey"}
// });
// static ENUM_FILTERS_WITH_AGGREGATE: Lazy<HashSet<&str>> = Lazy::new(|| {
//     ENUM_FILTERS.bitor(&hashset!{"_count"})
// });

// pub fn or_to_shape(&self) -> Shape {
//     let mut result = Shape::new(indexmap! {});
//     let mut times = 0;
//     if self.is_or() {
//         for input in self.as_or().unwrap() {
//             if let Some(shape) = input.as_shape() {
//                 result.extend(shape.clone().into_iter());
//                 times += 1;
//             }
//         }
//     }
//     if times > 1 {
//         result.iter_mut().for_each(|(_, input)| {
//             if let Some(t) = input.as_type_mut() {
//                 *t = t.to_optional();
//             }
//         })
//     }
//     result
// }