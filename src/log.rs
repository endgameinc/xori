// log.rs

#[macro_export]
macro_rules! debug {
    ($fmt:expr) => (
        #[cfg(debug_assertions)]
        print!(concat!(" [DEBUG] ",$fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (
        #[cfg(debug_assertions)]
        print!(concat!(" [DEBUG] ", $fmt, "\n"), $($arg)*));
}

#[macro_export]
macro_rules! disasm_debug {
    ($fmt:expr) => (
        #[cfg(test)]
        #[cfg(debug_assertions)]
        print!(concat!(" [DEBUG] ",$fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (
        #[cfg(test)]
        #[cfg(debug_assertions)]
        print!(concat!(" [DEBUG] ", $fmt, "\n"), $($arg)*));
}

macro_rules! error {
    ($fmt:expr) => (print!(concat!("[ERROR] ",$fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!("[ERROR] ", $fmt, "\n"), $($arg)*));
}

#[allow(unused_macros)]
macro_rules! info {
    ($fmt:expr) => (print!(concat!("[INFO] ",$fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => (print!(concat!("[INFO] ", $fmt, "\n"), $($arg)*));
}