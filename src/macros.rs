#[macro_export]
macro_rules! cast_data {
    ($target: expr, $pattern: path) => {{
        if let $pattern(a) = $target {
            a
        } else {
            panic!("Variant mismatch {}", stringify!($pattern));
        }
    }};
}
