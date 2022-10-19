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

#[macro_export]
macro_rules! type_object {
    ($target: ident, $pattern: literal) => {
        impl TypedObject<'static> for $target {
            const TYPE: &'static str = $pattern;
        }
    };
}
