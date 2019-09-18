/// Given an expression that returns a Result, return the error if there is one.
/// Otherwise, keep on trucking.
macro_rules! coalesce_result {
    ( $x:expr ) => {
        {
            let maybe_error = $x;
            match maybe_error { Result::Err(_) => return { maybe_error }, _ => {} }
        }
    };
}
