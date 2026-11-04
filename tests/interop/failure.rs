use std::{fmt, panic::Location};

pub struct Failure(pub String);
pub type TestResult<T = ()> = Result<T, Failure>;

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Convert fallible API results and required optional values into test errors.
pub trait Required<T> {
    #[track_caller]
    fn required(self) -> TestResult<T>;
}

impl<T, E: fmt::Debug> Required<T> for Result<T, E> {
    #[track_caller]
    fn required(self) -> TestResult<T> {
        let location = Location::caller();
        self.map_err(|error| Failure(format!("{error:?} at {location}")))
    }
}

impl<T> Required<T> for Option<T> {
    #[track_caller]
    fn required(self) -> TestResult<T> {
        let location = Location::caller();
        self.ok_or_else(|| Failure(format!("Required value is missing at {location}")))
    }
}

// Protocol mismatches are ordinary test failures, not unwinding panics.
macro_rules! check {
    ($condition:expr $(,)?) => {
        check!($condition, "Check failed: {}", stringify!($condition))
    };
    ($condition:expr, $($message:tt)+) => {
        if !$condition {
            return Err(crate::interop::Failure(format!("{} at {}:{}", format_args!($($message)+), file!(), line!())));
        }
    };
}

macro_rules! check_eq {
    ($left:expr, $right:expr $(,)?) => {
        check_eq!($left, $right, "{} == {}", stringify!($left), stringify!($right))
    };
    ($left:expr, $right:expr, $($message:tt)+) => {
        match (&$left, &$right) {
            (left, right) => check!(left == right, "{}: actual {left:?}, expected {right:?}", format_args!($($message)+)),
        }
    };
}
